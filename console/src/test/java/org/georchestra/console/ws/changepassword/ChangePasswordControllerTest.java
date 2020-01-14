package org.georchestra.console.ws.changepassword;

import org.georchestra.console.ds.AccountDaoImpl;
import org.georchestra.console.ds.DataServiceException;
import org.georchestra.console.ds.OrgsDao;
import org.georchestra.console.ds.RoleDaoImpl;
import org.georchestra.console.ws.utils.LogUtils;
import org.georchestra.console.ws.utils.PasswordUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.support.SessionStatus;

import javax.naming.Name;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertTrue;

public class ChangePasswordControllerTest {

    private ChangePasswordFormController ctrl;
    private LdapTemplate ldapTemplate;
    private LogUtils mockLogUtils;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private Model model;
    private ChangePasswordFormBean formBean;
    private BindingResult result;
    private SessionStatus sessionStatus;

    @Before
    public void setUp() {
        ldapTemplate = Mockito.mock(LdapTemplate.class);

        RoleDaoImpl roleDao = new RoleDaoImpl();
        roleDao.setLdapTemplate(ldapTemplate);

        OrgsDao orgsDao = new OrgsDao();
        orgsDao.setLdapTemplate(ldapTemplate);
        orgsDao.setOrgSearchBaseDN("ou=orgs");

        AccountDaoImpl dao = new AccountDaoImpl(ldapTemplate);
        dao.setUserSearchBaseDN("ou=users");
        dao.setOrgSearchBaseDN("ou=orgs");
        dao.setOrgSearchBaseDN("ou=orgs");
        ctrl = new ChangePasswordFormController(dao);
        ctrl.passwordUtils = new PasswordUtils();

        model = Mockito.mock(Model.class);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        formBean = new ChangePasswordFormBean();
        result = Mockito.mock(BindingResult.class);
        sessionStatus = Mockito.mock(SessionStatus.class);

        mockLogUtils = Mockito.mock(LogUtils.class);
        ctrl.logUtils = mockLogUtils;
    }

    @Test
    public void testInitForm() {
        WebDataBinder dataBinder = new WebDataBinder(getClass());
        ctrl.initForm(dataBinder);

        assertTrue(Arrays.asList(dataBinder.getAllowedFields()).contains("password"));
        assertTrue(Arrays.asList(dataBinder.getAllowedFields()).contains("confirmPassword"));
    }

    @Test
    public void testSetupFormForbidden() throws Exception {
        // No header
        ctrl.setupForm(request, response, "notme", model);

        assertTrue(response.getStatus() == HttpServletResponse.SC_FORBIDDEN);

        // With security header, but no match (NPE caught)
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        request.addHeader("sec-username", "me");

        ctrl.setupForm(request, response, "notme", model);

        assertTrue(response.getStatus() == HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    public void testSetupForm() throws Exception {
        request.addHeader("sec-username", "me");

        // regular case
        String ret = ctrl.setupForm(request, response, "me", model);

        assertTrue(ret.equals("changePasswordForm"));
    }

    @Test
    public void testChangePasswordFormInvalid() throws Exception {
        formBean.setUid("pmauduit");
        formBean.setPassword("monkey12");
        formBean.setConfirmPassword("monkey123");
        request.addHeader("sec-username", "pmauduit");
        Mockito.when(result.hasErrors()).thenReturn(true);

        String ret = ctrl.changePassword(request, response, model, formBean, result, sessionStatus);

        assertTrue(ret.equals("changePasswordForm"));
    }

    @Test
    public void testChangePasswordSuccess() throws Exception {
        formBean.setUid("pmauduit");
        formBean.setPassword("monkey123");
        formBean.setConfirmPassword("monkey123");
        request.addHeader("sec-username", "pmauduit");
        Mockito.when(result.hasErrors()).thenReturn(false);
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("success", true);
        Mockito.when(model.asMap()).thenReturn(map);
        Mockito.when(ldapTemplate.lookupContext((Name) Mockito.any()))
                .thenReturn(Mockito.mock(DirContextOperations.class));

        String ret = ctrl.changePassword(request, response, model, formBean, result, sessionStatus);

        assertTrue(ret.equals("changePasswordForm"));
        assertTrue(((Boolean) model.asMap().get("success")).booleanValue() == true);
    }

    @Test
    public void testChangePasswordDataServiceException() throws Exception {
        formBean.setUid("pmauduit");
        formBean.setPassword("monkey123");
        formBean.setConfirmPassword("monkey123");
        request.addHeader("sec-username", "pmauduit");
        Mockito.when(result.hasErrors()).thenReturn(false);
        Mockito.doThrow(DataServiceException.class).when(ldapTemplate).lookupContext((Name) Mockito.any());

        try {
            ctrl.changePassword(request, response, model, formBean, result, sessionStatus);
        } catch (Throwable e) {
            assertTrue(e instanceof IOException);
        }
    }

    @Test
    public void testChangePasswordUidMismatch() throws Exception {
        formBean.setUid("pmauduit1");

        request.addHeader("sec-username", "pmauduit");

        String ret = ctrl.changePassword(request, response, model, formBean, result, sessionStatus);
        assertTrue(ret == null);
    }

    @Test
    public void testChangePasswordMissingHeaders() throws Exception {
        formBean.setUid("pmauduit1");

        String ret = ctrl.changePassword(request, response, model, formBean, result, sessionStatus);
        assertTrue(ret == null);
    }

    @Test
    public void testChangePasswordFormBean() {
        ChangePasswordFormBean tested = new ChangePasswordFormBean();
        tested.setConfirmPassword("monkey123");
        tested.setUid("1");
        tested.setPassword("monkey123");

        assert ("1".equals(tested.getUid()));
        assert ("monkey123".equals(tested.getPassword()));
        assert ("monkey123".equals(tested.getConfirmPassword()));
        assert (tested.toString()
                .equals("ChangePasswordFormBean [uid=1, confirmPassword=monkey123, password=monkey123]"));
    }
}
