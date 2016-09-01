/*
 * Copyright (C) 2009-2016 by the geOrchestra PSC
 *
 * This file is part of geOrchestra.
 *
 * geOrchestra is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * geOrchestra is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * geOrchestra.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.georchestra.cas.ldap;

import java.security.GeneralSecurityException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.naming.directory.SearchControls;
import javax.security.auth.login.AccountException;
import javax.security.auth.login.LoginException;
import javax.validation.constraints.NotNull;

import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.LdapAuthenticationHandler;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.UsernamePasswordCredential;
import org.jasig.cas.authentication.principal.Principal;
import org.ldaptive.BindRequest;
import org.ldaptive.Connection;
import org.ldaptive.Credential;
import org.ldaptive.DefaultConnectionFactory;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.Response;
import org.ldaptive.SearchFilter;
import org.ldaptive.SearchOperation;
import org.ldaptive.SearchRequest;
import org.ldaptive.SearchResult;
import org.ldaptive.SearchScope;
import org.ldaptive.auth.Authenticator;

/**
 * Extends Ldap authentication handler by checking whether the user is pending
 * or valid. Also adds some extra fields to be released by the OpenId Attribute
 * release process.
 * 
 *
 * @author Jesse Eichar, Pierre Mauduit.
 */
public class GeorchestraLdapAuthenticationHandler extends LdapAuthenticationHandler {

    private String adminUser;
    private String adminPassword;
    private String baseDn;
    private String groupSearchFilter;
    private String groupRoleAttribute;
    private String pendingGroupName;
   
    private Pattern orgMembershipRegex = Pattern.compile("cn=(.*),ou=orgs,dc=georchestra,dc=org");
    private String orgBase = "ou=orgs,dc=georchestra,dc=org";
    
    private String orgIdField = "destinationIndicator";
    private String orgDnField = "o";

    private String userBaseDn = "ou=users,dc=georchestra,dc=org";

    public static String ORG_ID_KEY   = "org_id";
    public static String ORG_NAME_KEY = "org_name";
    
    private SearchControls searchControls = new SearchControls();

    private DefaultConnectionFactory connectionFactory;

    public void setAdminUser(String adminUser) {
        this.adminUser = adminUser;
    }

    public void setAdminPassword(String adminPassword) {
        this.adminPassword = adminPassword;
    }

    public void setBaseDn(String baseDn) {
        this.baseDn = baseDn;
    }

    public void setGroupSearchFilter(String groupSearchFilter) {
        this.groupSearchFilter = groupSearchFilter;
    }

    public void setGroupRoleAttribute(String groupRoleAttribute) {
        this.groupRoleAttribute = groupRoleAttribute;
    }

    public void setPendingGroupName(String pendingGroupName) {
        this.pendingGroupName = pendingGroupName;
    }
    /**
     * Creates a new authentication handler that delegates to the given authenticator.
     *
     * @param authenticator Ldaptive authenticator component.
     */
    public GeorchestraLdapAuthenticationHandler(@NotNull Authenticator authenticator,
                                                @NotNull String adminUser,
                                                @NotNull String adminPassword,
                                                @NotNull String baseDn,
                                                @NotNull String groupSearchFilter,
                                                @NotNull String groupRoleAttribute,
                                                @NotNull String pendingGroupName) {
        super(authenticator);
        this.adminUser = adminUser;
        this.adminPassword = adminPassword;
        this.baseDn = baseDn;
        this.groupSearchFilter = groupSearchFilter;
        this.groupRoleAttribute = groupRoleAttribute;
        this.pendingGroupName = pendingGroupName;
    }

    @Override
    protected HandlerResult authenticateUsernamePasswordInternal(UsernamePasswordCredential upc)
            throws GeneralSecurityException, PreventedException {
        final HandlerResult handlerResult = super.authenticateUsernamePasswordInternal(upc);

        final Connection conn = this.connectionFactory.getConnection();
        try {
            BindRequest bindRequest = new BindRequest(adminUser, new Credential(adminPassword));
            conn.open(bindRequest);

            SearchOperation search = new SearchOperation(conn);
            final String searchFilter = this.groupSearchFilter.replace("{1}", upc.getUsername());
            SearchResult result = search.execute(
                    new SearchRequest(this.baseDn, searchFilter, this.groupRoleAttribute)).getResult();

            if (result.getEntries().isEmpty()) {
                throw new AccountException("User is not part of any groups.");
            }
            for (LdapEntry entry : result.getEntries()) {
                final Collection<String> groupNames = entry.getAttribute(this.groupRoleAttribute).getStringValues();
                for (String name : groupNames) {
                    if (name.equals(this.pendingGroupName)) {
                        throw new AccountException("User is still a pending user.");
                    }
                }
            }
        } catch (LdapException e) {
            throw new PreventedException("Unexpected LDAP error", e);
        } finally {
            conn.close();
        }

        return handlerResult;
    }
    @Override
    protected Principal createPrincipal(final String username, final LdapEntry ldapEntry) throws LoginException {
        Principal p = super.createPrincipal(username, ldapEntry);
        String orgName = getOrganisationName(username);
        if (orgName != null) {
            String orgId = getOrganisationId(orgName);
            if (orgId != null) {
                Map<String, Object> newMap = new HashMap<String, Object>(p.getAttributes());
                newMap.put(ORG_ID_KEY, orgId);
                newMap.put(ORG_NAME_KEY, orgName);
                return this.principalFactory.createPrincipal(p.getId(), newMap);
            } else {
                logger.warn("Unable to find the organisation id.");
            }
        } else {
            logger.warn("Unable to find the organisation name.");
        }
        return p;
    }
    
    private String getOrganisationName(final String username) {
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
                response = new SearchOperation(connection).execute(createMemberOfRequest(username));
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
    
    private String getOrganisationId(final String orgCn) {
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
                response = new SearchOperation(connection).execute(createOrgRequest(orgCn));
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

    private SearchRequest createOrgRequest(final String orgCn) {
        final SearchRequest request = new SearchRequest();
        request.setBaseDn(orgBase);
        request.setSearchFilter(new SearchFilter(String.format("(&(%s=%s)(objectClass=organization))", orgDnField, orgCn)));
        request.setReturnAttributes(orgIdField);
        request.setSearchScope(SearchScope.ONELEVEL);
        request.setSizeLimit(this.searchControls.getCountLimit());
        request.setTimeLimit(this.searchControls.getTimeLimit());
        return request;
    }

    private SearchRequest createMemberOfRequest(final String username) {
        final SearchRequest request = new SearchRequest();
        request.setBaseDn(this.userBaseDn);
        request.setSearchFilter(new SearchFilter(String.format("%s=%s", "uid", username)));
        request.setReturnAttributes("memberOf");
        request.setSearchScope(SearchScope.ONELEVEL);
        request.setSizeLimit(this.searchControls.getCountLimit());
        request.setTimeLimit(this.searchControls.getTimeLimit());
        return request;
    }
    public void setConnectionFactory(DefaultConnectionFactory connectionFactory) {
        this.connectionFactory = connectionFactory;
    }
}
