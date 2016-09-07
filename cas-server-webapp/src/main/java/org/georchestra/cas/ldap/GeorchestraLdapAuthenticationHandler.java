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
import org.ldaptive.ConnectionFactory;
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
        //ConnectionFactory connectionFactory, SearchControls searchControls,
        //Pattern orgMembershipRegex, String username, String userBaseDn
        
        String orgName = GeorchestraLdapUtils.getOrganisationName(connectionFactory,
                searchControls, orgMembershipRegex, username, userBaseDn);
        if (orgName != null) {
            //    public static String getOrganisationId(final String orgCn, final ConnectionFactory connectionFactory,
            // SearchControls searchControls, String orgBase, String orgDnField, String orgIdField)
            
            String orgId = GeorchestraLdapUtils.getOrganisationId(connectionFactory, searchControls, orgName,
                    orgBase, orgDnField, orgIdField);
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



    public void setConnectionFactory(DefaultConnectionFactory connectionFactory) {
        this.connectionFactory = connectionFactory;
    }
}
