package org.georchestra.cas.ldap;

import java.util.Collection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.naming.directory.SearchControls;

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
 * Utility class used to factor code across custom geOrchestra classes.
 *
 * @author pmauduit
 *
 */
public class GeorchestraLdapUtils {
    private final static Logger logger = LoggerFactory.getLogger(GeorchestraLdapUtils.class);

    public static String getOrganisationName(ConnectionFactory connectionFactory, SearchControls searchControls,
            Pattern orgMembershipRegex, String username, String userBaseDn) {
        Connection connection = null;
        String orgCn = null;
        try {
            try {
                connection = connectionFactory.getConnection();
                connection.open();
            } catch (final LdapException e) {
                throw new RuntimeException("Failed getting LDAP connection", e);
            }
            Response<SearchResult> response;
            try {
                response = new SearchOperation(connection).execute(createMemberOfRequest(username, userBaseDn, searchControls));
            } catch (final LdapException e) {
                throw new RuntimeException("Failed executing LDAP query on user: " + username, e);
            }
            SearchResult result = response.getResult();
            // step 2

            for (final LdapEntry entry : result.getEntries()) {
               for (LdapAttribute att : entry.getAttributes()) {
                   Collection<String> attVals = att.getStringValues();
                   for (String attVal : attVals) {
                        if (attVal != null && attVal.matches(orgMembershipRegex.toString())) {
                            Matcher m = orgMembershipRegex.matcher(attVal);
                            if (m.find()) {
                                logger.debug("Found organisation membership: " + attVal);
                                orgCn = m.group(1);
                                break;
                            }
                        }
                    }
               }
               // abort after the first user found
               break;
            }
            } finally {
                if (connection != null && connection.isOpen()) {
                    try {
                        connection.close();
                    } catch (final Exception ex) {
                        logger.warn("Could not close ldap connection", ex);
                    }
                }
            }
        return orgCn;   
    }
    
    public static String getOrganisationId(final ConnectionFactory connectionFactory, SearchControls searchControls,
            final String orgCn, String orgBase, String orgDnField, String orgIdField) {
        Connection connection = null;
        String orgId = null;
        Response<SearchResult> response = null;

        try {
            try {
                connection = connectionFactory.getConnection();
                connection.open();
            } catch (final LdapException e) {
                throw new RuntimeException("Failed getting LDAP connection", e);
            }
            try {
                response = new SearchOperation(connection).execute(createOrgRequest(orgCn, orgBase, orgDnField, orgIdField, searchControls));
            } catch (final LdapException e) {
                throw new RuntimeException("Failed executing LDAP query ", e);
            }
            SearchResult result = response.getResult();
            for (final LdapEntry entry : result.getEntries()) {
                for (LdapAttribute att : entry.getAttributes()) {
                    orgId = att.getStringValue();
                    break;
                }
                break;
            }
            if (orgId == null) {
                logger.warn("Could not find the organization id for organization" + orgCn);
            } else {
                return orgId;
            }
        } finally {
            if (connection != null && connection.isOpen()) {
                try {
                    connection.close();
                } catch (final Exception ex) {
                    logger.warn("Could not close ldap connection", ex);
                }
            }
        }
        return orgId;
    }
    
    private static SearchRequest createOrgRequest(final String orgCn, String orgBase, String orgDnField, String orgIdField, SearchControls searchControls) {
        final SearchRequest request = new SearchRequest();
        request.setBaseDn(orgBase);
        request.setSearchFilter(new SearchFilter(String.format("(&(%s=%s)(objectClass=organization))", orgDnField, orgCn)));
        request.setReturnAttributes(orgIdField);
        request.setSearchScope(SearchScope.ONELEVEL);
        request.setSizeLimit(searchControls.getCountLimit());
        request.setTimeLimit(searchControls.getTimeLimit());
        return request;
    }
    
    private static SearchRequest createMemberOfRequest(final String username, String userBaseDn, SearchControls searchControls) {
        final SearchRequest request = new SearchRequest();
        request.setBaseDn(userBaseDn);
        request.setSearchFilter(new SearchFilter(String.format("%s=%s", "uid", username)));
        request.setReturnAttributes("memberOf");
        request.setSearchScope(SearchScope.ONELEVEL);
        request.setSizeLimit(searchControls.getCountLimit());
        request.setTimeLimit(searchControls.getTimeLimit());
        return request;
    }
}
