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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class OktaAuthentication implements AuthenticationProvider, InitializingBean {

    private static final Logger LOGGER = Logger.getLogger( OktaAuthentication.class.getName() );

    private String issuer;
    private String audience;
    private String securedRoute;
    private String accessScope;

    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final String token = ((OktaJwtToken) authentication).getJwt();


        LOGGER.log(Level.INFO, "*** Attempting Authentication ***");
        Map<String, Object> jwtClaims = decodeJwt(token);

        OktaJwtToken tokenAuth = (OktaJwtToken) authentication;
        tokenAuth.setAuthenticated(true);
        tokenAuth.setPrincipal(new OktaDetails(jwtClaims, this.getAccessScope()));
        tokenAuth.setDetails(jwtClaims);

        return authentication;
    }

    public boolean supports(Class<?> authentication) {
        return OktaJwtToken.class.isAssignableFrom(authentication);
    }


    protected String getIssuer() {
        return issuer;
    }
    protected void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    protected String getAudience() {
        return audience;
    }
    protected void setAudience(String audience) { this.audience = audience; }

    protected String getSecuredRoute() {
        return securedRoute;
    }
    protected void setSecuredRoute(String securedRoute) {
        this.securedRoute = securedRoute;
    }

    protected String getAccessScope() { return accessScope; }
    protected void setAccessScope(String accessScope) { this.accessScope = accessScope; }

    /**
     *  Decode and verify JWT token using jose4j JWT library
     * @param jwt
     * @return
     */
    public Map decodeJwt(String jwt) {
        // Create a new JsonWebSignature
        JsonWebSignature jws = new JsonWebSignature();
        try {jws.setCompactSerialization(jwt);}
        catch (JoseException e) { e.printStackTrace(); }

        // Build a JwtConsumer that doesn't check signatures or do any validation.
        JwtConsumer firstPassJwtConsumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();

        //The first JwtConsumer is basically just used to parse the JWT into a JwtContext object.
        JwtContext jwtContext = null;
        try {jwtContext = firstPassJwtConsumer.process(jwt);}
        catch (InvalidJwtException e) {
            LOGGER.log(Level.SEVERE, e.getMessage());
        }
        // From the JwtContext we can get the issuer, or whatever else we might need,
        // to lookup or figure out the kind of validation policy to apply
        String issuer = null;
        try {
            issuer = jwtContext.getJwtClaims().getIssuer();
        }
        catch (MalformedClaimException e) {
            LOGGER.log(Level.SEVERE, e.getMessage());
        }

        ObjectMapper mapper = new ObjectMapper();
        Map discoveryDoc = new HashMap<String, Object>();

        // Convert JSON string to Map
        try {
            discoveryDoc = mapper.readValue(getDiscoveryDocument(getIssuer()),
                    new TypeReference<Map<String, Object>>(){});
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, e.getMessage());
        }

        Object jwksUri = discoveryDoc.get("jwks_uri");
        HttpsJwks httpsJwks = new HttpsJwks(jwksUri.toString());
        HttpsJwksVerificationKeyResolver httpsJwksKeyResolver = new HttpsJwksVerificationKeyResolver(httpsJwks);

        JwtConsumer secondPassJwtConsumer = new JwtConsumerBuilder()
                .setExpectedIssuer(issuer)
                .setVerificationKeyResolver(httpsJwksKeyResolver)
                .setRequireExpirationTime()
                .setAllowedClockSkewInSeconds(30)
                .setRequireSubject()
                .setExpectedAudience(this.getAudience())
                .build();

        try {
            secondPassJwtConsumer.processContext(jwtContext);
            return secondPassJwtConsumer.processToClaims(jwt).getClaimsMap();

        } catch (InvalidJwtException e) {
            LOGGER.log(Level.SEVERE, e.getMessage());
        }
        return null;
    }

    public static String getDiscoveryDocument(String issuer) {
        HttpURLConnection connection = null;

        try {
            //Create connection
            URL url = new URL(issuer + "/.well-known/openid-configuration");
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");

            //Get Response from Discovery URL
            BufferedReader rd = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = rd.readLine()) != null) {
                response.append(line);
                response.append('\r');

            }
            rd.close();
            return response.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    public void afterPropertiesSet() throws Exception {
        if (audience == null){
            LOGGER.log(Level.SEVERE, "Audience must be specified");
        }
        else if(securedRoute == null) {
            LOGGER.log(Level.SEVERE, "Must specify route for accessToken authentication/validation");
        }
    }
}

