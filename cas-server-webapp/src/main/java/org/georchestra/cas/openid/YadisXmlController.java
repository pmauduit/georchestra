package org.georchestra.cas.openid;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class YadisXmlController {

    private String serverPrefix;
    
    @RequestMapping("/yadis/yadis.xml")
    public void getYadis(HttpServletRequest request, HttpServletResponse response) {
        InputStream is = this.getClass().getResourceAsStream("/etc/yadis.xml.tmpl");
        if (is == null) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        try {
            String yadisXml = IOUtils.toString(is);
            yadisXml = yadisXml.replace("${server.prefix}", this.serverPrefix);
            response.getOutputStream().write(yadisXml.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        } finally {
            IOUtils.closeQuietly(is);
        }
    }
    
    public void setServerPrefix(String serverPrefix) {
        this.serverPrefix = serverPrefix;
    }
}
