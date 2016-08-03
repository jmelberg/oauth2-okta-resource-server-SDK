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

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class EntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest req, HttpServletResponse res, AuthenticationException authException)
            throws IOException, ServletException {
        final PrintWriter writer = res.getWriter();
        if (isPreflight(req)) {
            res.setStatus(HttpServletResponse.SC_NO_CONTENT);
        } else {
            res.sendError(HttpServletResponse.SC_FORBIDDEN, authException.getMessage());
            writer.println("HTTP Status " + HttpServletResponse.SC_FORBIDDEN + " - " + authException.getMessage());
        }
    }

    /** Checks if this is a X-domain pre-flight request  */
    private boolean isPreflight(HttpServletRequest request) {
        return "OPTIONS".equals(request.getMethod());
    }
}
