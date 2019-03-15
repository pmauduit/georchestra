/*
 * Copyright (C) 2009-2018 by the geOrchestra PSC
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

package org.georchestra.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.regex.Pattern;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
<<<<<<< HEAD
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
=======
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
>>>>>>> origin/17.12
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

/**
 * If the user-agent of the client is one of the supported user-agents then send a basic authentication request.
 * <p/>
 * Normally the security proxy is configured to redirect to cas login if a user is not authenticated and tries to access a secured page.
 * This behaviour is fine for users visiting the site via browsers, however user with other clients usch as QGis or ARcGIS that use
 * basic authentication expect a basic authentication challenge in order to authenticate.
 * <p/>
 * This filter will check the user-agent and, if a match is found, send a basic auth challenge.
 * Note that it first checks if the user had already been authenticated, and doesn't send a basic auth challenge in that case.
 * <p/>
 * User: Jesse
 * Date: 11/7/13
 * Time: 9:44 AM
 */
public class BasicAuthChallengeByUserAgent extends BasicAuthenticationFilter {

    public BasicAuthChallengeByUserAgent(AuthenticationManager authenticationManager,
            AuthenticationEntryPoint authenticationEntryPoint) {
        super(authenticationManager, authenticationEntryPoint);
    }

    private final List<Pattern> _userAgents = new ArrayList<Pattern>();
    private boolean ignoreHttps = false;
    private static final Log LOGGER = LogFactory.getLog(BasicAuthChallengeByUserAgent.class.getPackage().getName());
    private AuthenticationException _exception = new AuthenticationException("No basic authentication credentials provided") {};

    public void init() throws IOException {
        // GeorchestraConfiguration is a regular spring bean, which won't be
        // accessible from this bean (which is a spring-security one). We have no
        // other choice than doing configuration by hand.
        String datadir = System.getProperty("georchestra.datadir");
        Properties uaProps = new Properties();
        if (datadir != null) {
            File contextDatadir = new File(datadir, "security-proxy");
            if (! contextDatadir.exists()) {
                return;
            }
            FileInputStream fisProp = null;
            try {
                fisProp = new FileInputStream(new File(contextDatadir, "user-agents.properties"));
                InputStreamReader isrProp = new InputStreamReader(fisProp, "UTF8");
                _userAgents.clear();
                uaProps.load(isrProp);
            } finally {
                if (fisProp != null) {
                    fisProp.close();
                }
            }
        }
        if (! uaProps.isEmpty()) {
            int i = 0;
            String ua;
            while ((ua = uaProps.getProperty("useragent" + i + ".value")) != null) {
                _userAgents.add(Pattern.compile(ua));
                i++;
            }
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response, FilterChain chain)
                    throws IOException, ServletException {
        if(!request.getScheme().equalsIgnoreCase("https") && ! ignoreHttps) {
            LOGGER.debug("not in HTTPS, skipping filter.");
            chain.doFilter(request, response);
            return;
        }

        if(!authenticationIsRequired()) {
            LOGGER.debug("the user has already been authenticated, skipping filter.");
            chain.doFilter(req, res);
            return;
        }

        final HttpServletRequest request = (HttpServletRequest) req;
        String auth = request.getHeader("Authorization");

        /* no valid Authorization header sent preemptively */
        if ((auth == null) || !auth.startsWith("Basic ")) {
            final String userAgent = request.getHeader("User-Agent");
            if (userAgentMatch(userAgent)) {
                /* UA matched, return a 401 directly to the client */
                LOGGER.debug("the user-agent matched and no Authorization header was sent, returning a 401.");
                getAuthenticationEntryPoint().commence(request, response, _exception);
            } else {
                LOGGER.debug("the user-agent does not match, skipping filter.");
                chain.doFilter(request, response);
            }
        } else {
            LOGGER.debug("Authorization header sent in the request, activating filter ...");
            super.doFilterInternal(request, response, chain);
        }
    }

    /*
     * Copied and adapted from the super class BasicAuthenticationFilter in Spring Security 3.2.10.RELEASE code
     */
    private boolean authenticationIsRequired() {
        // Only reauthenticate if username doesn't match SecurityContextHolder and user isn't authenticated
        // (see SEC-53)
        Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();

        if(existingAuth == null || !existingAuth.isAuthenticated()) {
            return true;
        }

        // Handle unusual condition where an AnonymousAuthenticationToken is already present
        // This shouldn't happen very often, as BasicProcessingFitler is meant to be earlier in the filter
        // chain than AnonymousAuthenticationFilter. Nevertheless, presence of both an AnonymousAuthenticationToken
        // together with a BASIC authentication request header should indicate reauthentication using the
        // BASIC protocol is desirable. This behaviour is also consistent with that provided by form and digest,
        // both of which force re-authentication if the respective header is detected (and in doing so replace
        // any existing AnonymousAuthenticationToken). See SEC-610.
        if (existingAuth instanceof AnonymousAuthenticationToken) {
            return true;
        }

        return false;
    }

    private boolean userAgentMatch(Object attribute) {
        if (attribute!=null) {
            for (Pattern userAgent : _userAgents) {
                if (userAgent.matcher(attribute.toString()).matches()) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Set the user-agents the string is parsed as a Regex expression.
     */
    public void setChallengeUserAgents(List<String> userAgents) {
        _userAgents.clear();
        for (String userAgent : userAgents) {
            _userAgents.add(Pattern.compile(userAgent));
        }
    }

    /**
     * Sets the ignoreHttps flag.
     * if set to true the filter is active even on regular non-SSL HTTP requests.
     */
    public void setIgnoreHttps(boolean f) {
        ignoreHttps = f;
    }
}
