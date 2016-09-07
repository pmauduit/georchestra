package org.georchestra.cas.ldap;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import javax.annotation.PostConstruct;
import javax.naming.directory.SearchControls;

import org.jasig.services.persondir.IPersonAttributes;
import org.jasig.services.persondir.support.AbstractQueryPersonAttributeDao;
import org.jasig.services.persondir.support.CaseInsensitiveAttributeNamedPersonImpl;
import org.jasig.services.persondir.support.CaseInsensitiveNamedPersonImpl;
import org.ldaptive.Connection;
import org.ldaptive.ConnectionFactory;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.Response;
import org.ldaptive.SearchFilter;
import org.ldaptive.SearchOperation;
import org.ldaptive.SearchRequest;
import org.ldaptive.SearchResult;
import org.ldaptive.SearchScope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Does basically the same as LdaptivePersonAtributeDao, but also finds the
 * org_uid and org_name needed for PPIGE openId interaction with isogeo.
 * 
 * The main content of this class has been stolen from
 * {@link org.jasig.services.persondir.support.ldap.LdaptivePersonAttributeDao}
 * with a subtle mix of GeorchestraAuthenticationHandler's code.
 * 
 * @author pmauduit
 *
 */
public class GeorchestraAttributeRepository extends AbstractQueryPersonAttributeDao<SearchFilter> {

    /** Logger instance. **/
    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /** Search base DN. */
    private String baseDN;

    /** Search controls. */
    private SearchControls searchControls = new SearchControls();

    /** LDAP connection factory. */
    private ConnectionFactory connectionFactory;

    /** LDAP search scope. */
    private SearchScope searchScope;

    /** LDAP search filter. */
    private String searchFilter;

    /** LDAP attributes to fetch from search results. */
    private String[] attributes;
    
    /** geOrchestra PPIGE specific attributes */
    private Pattern orgMembershipRegex = Pattern.compile("cn=(.*),ou=orgs,dc=georchestra,dc=org");
    private String orgBase = "ou=orgs,dc=georchestra,dc=org";
    
    private String orgIdField = "destinationIndicator";
    private String orgDnField = "o";

    private String userBaseDn = "ou=users,dc=georchestra,dc=org";

    public static String ORG_ID_KEY   = "org_id";
    public static String ORG_NAME_KEY = "org_name";

    public GeorchestraAttributeRepository() {
        super();
    }

    /**
     * Sets the base DN of the LDAP search for attributes.
     *
     * @param dn
     *            LDAP base DN of search.
     */
    public void setBaseDN(final String dn) {
        this.baseDN = dn;
    }

    /**
     * Sets the LDAP search filter used to query for person attributes.
     *
     * @param filter
     *            Search filter of the form "(usernameAttribute={0})" where {0}
     *            and similar ordinal placeholders are replaced with query
     *            parameters.
     */
    public void setSearchFilter(final String filter) {
        this.searchFilter = filter;
    }

    /**
     * Sets a number of parameters that control LDAP search semantics including
     * search scope, maximum number of results retrieved, and search timeout.
     *
     * @param searchControls
     *            LDAP search controls.
     */
    public void setSearchControls(final SearchControls searchControls) {
        this.searchControls = searchControls;
    }

    /**
     * Sets the connection factory that produces LDAP connections on which
     * searches occur. It is strongly recommended that this be a
     * <code>PooledConnecitonFactory</code> object.
     *
     * @param connectionFactory
     *            LDAP connection factory.
     */
    public void setConnectionFactory(final ConnectionFactory connectionFactory) {
        this.connectionFactory = connectionFactory;
    }

    /**
     * Initializes the object after properties are set.
     */
    @PostConstruct
    public void initialize() {
        for (final SearchScope scope : SearchScope.values()) {
            if (scope.ordinal() == this.searchControls.getSearchScope()) {
                this.searchScope = scope;
            }
        }
        this.attributes = getResultAttributeMapping().keySet().toArray(new String[getResultAttributeMapping().size()]);
    }

    @Override
    protected List<IPersonAttributes> getPeopleForQuery(final SearchFilter filter, final String userName) {
        Connection connection = null;
        try {
            try {
                connection = this.connectionFactory.getConnection();
                connection.open();
            } catch (final LdapException e) {
                throw new RuntimeException("Failed getting LDAP connection", e);
            }
            final Response<SearchResult> response;
            try {
                response = new SearchOperation(connection).execute(createRequest(filter));
            } catch (final LdapException e) {
                throw new RuntimeException("Failed executing LDAP query " + filter, e);
            }
            final SearchResult result = response.getResult();
            final List<IPersonAttributes> peopleAttributes = new ArrayList<IPersonAttributes>(result.size());
            for (final LdapEntry entry : result.getEntries()) {
                final IPersonAttributes person;
                final String userNameAttribute = this.getConfiguredUserNameAttribute();
                final Map<String, List<Object>> attributes = convertLdapEntryToMap(entry);
                
                /** geOrchestra PPIGE specific: adding orgName and orgId as attributes */
                String orgName = GeorchestraLdapUtils.getOrganisationName(connectionFactory,
                        searchControls, orgMembershipRegex, userName, userBaseDn);
                if (orgName != null) {
                    String orgId = GeorchestraLdapUtils.getOrganisationId(connectionFactory,
                            searchControls, orgName, orgBase, orgDnField, orgIdField);
                    if (orgId != null) {
                        attributes.put(ORG_ID_KEY, Arrays.asList(new Object[] { orgId }));
                        attributes.put(ORG_NAME_KEY, Arrays.asList(new Object[] { orgName }));                        
                    } else {
                        logger.warn("Unable to find the organisation id.");
                    }
                } else {
                    logger.warn("Unable to find the organisation name.");
                }
                
                if (attributes.containsKey(userNameAttribute)) {
                    person = new CaseInsensitiveAttributeNamedPersonImpl(userNameAttribute, attributes);
                } else {
                    person = new CaseInsensitiveNamedPersonImpl(userName, attributes);
                }
                peopleAttributes.add(person);
            }

            return peopleAttributes;
        } finally {
            closeConnection(connection);
        }
    }

    @Override
    protected SearchFilter appendAttributeToQuery(final SearchFilter filter, final String attribute,
            final List<Object> values) {
        final SearchFilter query;
        if (filter == null && values.size() > 0) {
            query = new SearchFilter(this.searchFilter);
            query.setParameter(0, values.get(0).toString());
            logger.debug("Constructed LDAP search query [{}]", query.format());
        } else {
            throw new UnsupportedOperationException("Multiple attributes not supported.");
        }
        return query;
    }

    /**
     * Creates a search request from a search filter.
     *
     * @param filter
     *            LDAP search filter.
     *
     * @return ldaptive search request.
     */
    private SearchRequest createRequest(final SearchFilter filter) {
        final SearchRequest request = new SearchRequest();
        request.setBaseDn(this.baseDN);
        request.setSearchFilter(filter);
        request.setReturnAttributes(this.attributes);
        request.setSearchScope(this.searchScope);
        request.setSizeLimit(this.searchControls.getCountLimit());
        request.setTimeLimit(this.searchControls.getTimeLimit());
        return request;
    }

    /**
     * Converts an ldaptive <code>LdapEntry</code> containing result entry
     * attributes into an attribute map as needed by Person Directory
     * components.
     *
     * @param entry
     *            Ldap entry.
     *
     * @return Attribute map.
     */
    private Map<String, List<Object>> convertLdapEntryToMap(final LdapEntry entry) {
        final Map<String, List<Object>> attributeMap = new LinkedHashMap<String, List<Object>>(entry.size());
        for (final LdapAttribute attr : entry.getAttributes()) {
            attributeMap.put(attr.getName(), new ArrayList<Object>(attr.getStringValues()));
        }
        logger.debug("Converted ldap DN entry [{}] to attribute map {}", entry.getDn(), attributeMap.toString());
        return attributeMap;
    }

    private void closeConnection(final Connection context) {
        if (context != null && context.isOpen()) {
            try {
                context.close();
            } catch (final Exception ex) {
                logger.warn("Could not close ldap connection", ex);
            }
        }
    }
}
