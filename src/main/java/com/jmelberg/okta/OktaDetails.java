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

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;


public class OktaDetails implements UserDetails {

    private static final Logger LOGGER = Logger.getLogger( OktaDetails.class.getName() );

    private Map<String, Object> claims;
    private Collection<GrantedAuthority> authorities;
    private String email;



    public OktaDetails(Map claims, String strategy) {
        this.claims = claims;
        this.setAuthorities(claims, strategy);
    }

    @Override
    public String getUsername() {
        return email;
    }

    public void setAuthorities(Map claims, String strategy) {
        this.authorities = new ArrayList();
        LOGGER.log(Level.INFO, "Available Claims: \n" + claims.toString());
        if (claims.containsKey("user_email")) {
            this.email = claims.get("user_email").toString();
        }
        if (claims.containsKey("scp")) {
            LOGGER.log(Level.INFO, "Found SCP: " + claims.get("scp"));
            if (claims.get("scp").toString().contains(strategy)) {
                LOGGER.log(Level.INFO, "Approved: " + strategy);
                this.authorities.add(new SimpleGrantedAuthority(strategy));
            }
        }
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public Object getClaimByName(String name) {
        return claims.get(name);
    }

    /** Required Methods -- Currently not used  */

    @Override
    public String getPassword() { return null; }

    @Override
    public boolean isAccountNonExpired() { return false; }

    @Override
    public boolean isAccountNonLocked() { return false; }

    @Override
    public boolean isCredentialsNonExpired() { return false; }

    @Override
    public boolean isEnabled() { return false; }


}


