package com.jmelberg.okta;

/** Author: Jordan Melberg **/

/**
 * Copyright (c) 2015-2016, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 *
 */

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

public class BeanFilter extends GenericFilterBean {
    private static final Logger LOGGER = Logger.getLogger( BeanFilter.class.getName() );

    @Autowired
    private AuthenticationManager authenticationManager;
    private AuthenticationEntryPoint entryPoint;

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        final HttpServletRequest request = (HttpServletRequest) req;
        final HttpServletResponse response = (HttpServletResponse) res;
        if (request.getMethod().equals("OPTIONS")) {
            // CORS request
            chain.doFilter(request, response);
            return;
        }
        final String jwt = getToken(request);
        if (jwt != null) {
            try {
                final Authentication authResult = authenticationManager.authenticate(new OktaJwtToken(jwt));
                SecurityContextHolder.getContext().setAuthentication(authResult);
            } catch (AuthenticationException failed) {
                SecurityContextHolder.clearContext();
                entryPoint.commence(request, response, failed);
                return;
            } catch (Exception e ) {
                LOGGER.log(Level.SEVERE, "Error: " + e.getLocalizedMessage());
            }
        }
        chain.doFilter(request, response);
    }

    protected String getToken(HttpServletRequest httpRequest) {
        final String authorizationHeader = httpRequest.getHeader("authorization");
        if (authorizationHeader == null) {
            // Error:  No Authorization header
            return null;
        }
        final String[] parts = authorizationHeader.split(" ");
        if (parts.length != 2) {
            // Error: Incorrect Format
            return null;
        }
        final String scheme = parts[0];
        final String credentials = parts[1];
        final Pattern pattern = Pattern.compile("^Bearer$", Pattern.CASE_INSENSITIVE);
        return pattern.matcher(scheme).matches() ? credentials : null;
    }

    public void setEntryPoint(AuthenticationEntryPoint entryPoint) {
        this.entryPoint = entryPoint;
    }
}
