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

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class OktaJwtToken extends AbstractAuthenticationToken {
    private final String jwt;
    private OktaDetails principal;

    public OktaJwtToken(String jwt) {
        super(null);
        this.jwt = jwt;
        setAuthenticated(false);
    }

    public String getJwt() { return jwt; }

    public Object getCredentials() {
        return null;
    }
    public Object getPrincipal() { return principal; }
    public void setPrincipal(OktaDetails p) { this.principal = p; }

    @SuppressWarnings("unchecked")
    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        return (Collection<GrantedAuthority>) principal.getAuthorities();
    }
}
