package org.georchestra.cas.ldap;

import static org.junit.Assert.assertTrue;

import java.lang.reflect.Method;
import java.util.Map;

import org.jasig.cas.authentication.principal.Principal;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.ldaptive.DefaultConnectionFactory;
import org.ldaptive.LdapEntry;
import org.springframework.util.ReflectionUtils;

/**
 * Test class for GeorchestraLdapAuthenticationHandler
 *   ____  ____ ___ ____ _____ 
 *  |  _ \|  _ \_ _/ ___| ____|
 *  | |_) | |_) | | |  _|  _|  
 *  |  __/|  __/| | |_| | |___ 
 *  |_|   |_|  |___\____|_____|
 *
 * Since I have no idea on how the remote LDAP will respond, I am going to TDD the class
 * using a real LDAP instead of mocking it.
 *
 * @author pmauduit
 *
 */

public class GeorchestraLdapAuthenticationHandlerTest {

    private final GeorchestraLdapAuthenticationHandler glah = new GeorchestraLdapAuthenticationHandler(null,
            null, null, "ou=roles,dc=georchestra,dc=org", "objectclass=GroupOfMembers", "member", "PENDING");

    @Before
    public void setUp() {
        DefaultConnectionFactory cf = new DefaultConnectionFactory("ldap://localhost:3389/");

        glah.setConnectionFactory(cf);
    }

    @Test
    @Ignore("Works only when ldap://localhost:3389/ is available and corresponds to a Preprod PPIGE LDAP tree")
    public void testGetPeopleForQuery() {
      Method m = ReflectionUtils.findMethod(glah.getClass(), "createPrincipal",
              String.class, LdapEntry.class);
      m.setAccessible(true);

      Object ret = ReflectionUtils.invokeMethod(m, glah, "pmauduit", new LdapEntry());

      assertTrue("unexpected return type, expected Principal", ret instanceof Principal);
      Map<String,Object> attrs = ((Principal) ret).getAttributes();
      String orgId   = attrs.get(GeorchestraLdapAuthenticationHandler.ORG_ID_KEY).toString();
      String orgName = attrs.get(GeorchestraLdapAuthenticationHandler.ORG_NAME_KEY).toString();

      assertTrue("Unexpected value for org id", orgId.equals("33640"));
      assertTrue("Unexpected value for org key", orgName.equals("CampToCamp"));
    }

    /**
     * Almost the same as the previous test, but on another user.
     */
    @Test
    @Ignore("Works only when ldap://localhost:3389/ is available and corresponds to a Preprod PPIGE LDAP tree")
    public void testGetPeopleForQueryAnotherAccount() {
        Method m = ReflectionUtils.findMethod(glah.getClass(), "createPrincipal",
                String.class, LdapEntry.class);
      m.setAccessible(true);

      Object ret = ReflectionUtils.invokeMethod(m, glah, "m.bessaguet", new LdapEntry());

      assertTrue("unexpected return type, expected Principal", ret instanceof Principal);
      Map<String,Object> attrs = ((Principal) ret).getAttributes();
      String orgId   = attrs.get(GeorchestraLdapAuthenticationHandler.ORG_ID_KEY).toString();
      String orgName = attrs.get(GeorchestraLdapAuthenticationHandler.ORG_NAME_KEY).toString();

      assertTrue("Unexpected value for org id", orgId.equals("2570"));
      assertTrue("Unexpected value for org key", orgName.equals("epf_npdc"));
    }
}
