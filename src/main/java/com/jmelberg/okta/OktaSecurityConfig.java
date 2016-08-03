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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

@Configuration
@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class OktaSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value(value = "${okta.issuer}")
    protected String issuer;

    @Value(value = "${okta.audience}")
    protected String audience;

    @Value(value = "${okta.securedRoute}")
    protected String securedRoute;

    @Value(value = "${okta.accessScope}")
    protected String accessScope;

    @Autowired
    @SuppressWarnings("SpringJavaAutowiringInspection")
    @Bean(name = "oktaAuthenticationManager")
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean(name = "authenticationProvider")
    public AuthenticationProvider authenticationProvider() {
        final OktaAuthentication authenticationProvider = new OktaAuthentication();
        authenticationProvider.setIssuer(issuer);
        authenticationProvider.setAudience(audience);
        authenticationProvider.setSecuredRoute(securedRoute);
        authenticationProvider.setAccessScope(accessScope);
        return authenticationProvider;
    }

    @Bean(name = "entryPoint")
    public AuthenticationEntryPoint entryPoint() {
        return new EntryPoint();
    }

    @Bean(name = "filter")
    public BeanFilter beanFilter(final AuthenticationEntryPoint entryPoint) {
        final BeanFilter filter = new BeanFilter();
        filter.setEntryPoint(entryPoint);
        return filter;
    }

    @Bean
    public CORSFilter corsFilter() {
        return new CORSFilter();
    }


    @Bean(name = "authenticationFilterRegistration")
    public FilterRegistrationBean authenticationFilterRegistration(final BeanFilter filter) {
        final FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
        filterRegistrationBean.setFilter(filter);
        filterRegistrationBean.setEnabled(false);
        return filterRegistrationBean;
    }

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                .antMatchers(HttpMethod.OPTIONS, "/**");
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        // Disable CSRF
        http
                .csrf()
                .disable()
                .addFilterAfter(beanFilter(entryPoint()), SecurityContextPersistenceFilter.class)
                .addFilterBefore(corsFilter(), BeanFilter.class);

        // Set Authentication/Authorization
        authorizeRequests(http);

        // Re-authentication of JWT token on every request
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    protected void authorizeRequests(final HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers(securedRoute)
                .authenticated()
                .antMatchers("/**")
                .permitAll();
    }


}
