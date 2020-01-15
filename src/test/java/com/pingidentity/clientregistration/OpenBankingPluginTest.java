/*
 * Copyright 2018 Ping Identity Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.pingidentity.clientregistration;

import com.pingidentity.clientregistration.constants.Constants;
import com.pingidentity.clientregistration.constants.DynamicClientSoftwareFields;
import com.pingidentity.sdk.oauth20.registration.ClientRegistrationException;
import com.pingidentity.sdk.oauth20.registration.DynamicClient;
import com.pingidentity.sdk.oauth20.registration.DynamicClientFields;
import org.jose4j.jwt.JwtClaims;
import org.junit.Assert;
import org.junit.Test;
import org.sourceid.oauth20.domain.DynamicOAuthClient;
import org.sourceid.oauth20.domain.ParamValues;

import java.util.*;

public class OpenBankingPluginTest
{
    private static final List<String> REDIRECT_URIS_1 =  Arrays.asList("https://localhost.com", "https://localhostone.com");
    private static final List<String> REDIRECT_URIS_2 =  Arrays.asList("https://localhost.com", "https://localhostinvalid.com");
    private static final List<String> REDIRECT_URIS_3 =  Arrays.asList("https://pingidentity.com", "https://google.com");

    private ClaimTranslator claimTranslator = new ClaimTranslator();


    static final String JWKS_1 = "https://localhost:9031/pf/JWKS";
    private static final String JWKS_2 = "https://localhostinvalid:9031/pf/JWKS";

    private DynamicClient getDynamicClient()
    {
        return new DynamicOAuthClient()
        {
            @Override
            public Map<String, ParamValues> getExtendedParams()
            {
                return new HashMap<>();
            }

            @Override
            public void setExtendedParams(Map<String, ParamValues> extendedParams)
            {
                //do nothing
            }
            @Override
            public Set<String> getClientMetadataKeys()
            {
                return new HashSet<>();
            }

        };
    }

    private JwtClaims populateClaims(String clientName, List<String> redirectUris, String jwksUri)
    {
        JwtClaims claims = new JwtClaims();
        claims.setClaim(DynamicClientSoftwareFields.SOFTWARE_CLIENT_NAME.getName(), "PF_test");
        claims.setClaim(Constants.ORG_NAME,"Ping");
        claims.setClaim(Constants.SOFTWARE_VERSION,"1.0");
        claims.setClaim(Constants.APPLICATION_TYPE, "web");


        claims.setIssuer("https://localhost:9031/as/token.oauth2");
        claims.setClaim(DynamicClientFields.GRANT_TYPES.getName(), Arrays.asList("client_credentials"));
        claims.setClaim(DynamicClientFields.CLIENT_NAME.getName(), clientName);
        claims.setClaim(DynamicClientFields.TOKEN_ENDPOINT_AUTH_METHOD.getName(),"private_key_jwt");

        claims.setClaim(DynamicClientFields.REDIRECT_URIS.getName(), redirectUris);
        claims.setClaim(DynamicClientFields.JWKS_URI.getName(), jwksUri);

        return claims;
    }

    private void setSoftwareRedirectUriJwksUri(JwtClaims claims, List<String> redirectUris, String softwareJwksUri)
    {
        claims.setClaim(DynamicClientSoftwareFields.SOFTWARE_REDIRECT_URIS.getName(), redirectUris);
        claims.setClaim(DynamicClientSoftwareFields.SOFTWARE_JWKS_ENDPOINT.getName(), softwareJwksUri);
    }


    /**
     * This method tests the functionality of using common redirect URIs and JWKS URI from request payload, software_statement and respective software_* fields.
     *
     */
    @Test
    public void testCommonUris()
    {
        DynamicClient client = getDynamicClient();

        String clientName = "testCommonRedirectUri";
        JwtClaims requestClaims = populateClaims(clientName, null, JWKS_1);
        setSoftwareRedirectUriJwksUri(requestClaims, null, JWKS_1);

        JwtClaims softwareStatementClaims = populateClaims(clientName, REDIRECT_URIS_2, JWKS_1);
        setSoftwareRedirectUriJwksUri(softwareStatementClaims, REDIRECT_URIS_2, JWKS_1);

        try
        {
            claimTranslator.processClaims(client, softwareStatementClaims);
            claimTranslator.processRequestJwtClaims(client, requestClaims, softwareStatementClaims);

        }
        catch(ClientRegistrationException e)
        {
            Assert.fail("Expected a common redirect URI but not obtained.");
        }

       //Commonly present URI is one of the redirect URIs and the rest aren't
       Assert.assertTrue(client.getRedirectUris().contains("https://localhost.com"));
       Assert.assertTrue(client.getRedirectUris().contains("https://localhostinvalid.com"));

       Assert.assertTrue(client.getJwksUrl().equals(JWKS_1));

    }


    /**
     * This method tests the functionality of using common redirect URIs and JWKS URI from request payload, software_statement and respective software_* fields.
     *
     */
    @Test
    public void testCommonRedirectUrisErrorSoftwareStatement()
    {
        DynamicClient client = getDynamicClient();

        String clientName = "testCommonRedirectUri";
        JwtClaims requestClaims = populateClaims(clientName, REDIRECT_URIS_1, JWKS_1);
        setSoftwareRedirectUriJwksUri(requestClaims, REDIRECT_URIS_1, JWKS_1);

        JwtClaims softwareStatementClaims = populateClaims(clientName, REDIRECT_URIS_2, JWKS_1);
        setSoftwareRedirectUriJwksUri(softwareStatementClaims, REDIRECT_URIS_3, JWKS_1);

        try
        {
            claimTranslator.processClaims(client, softwareStatementClaims);
            claimTranslator.processRequestJwtClaims(client, requestClaims, softwareStatementClaims);
            Assert.fail("Expected a ClientRegistrationException due to unavailability of common redirect uris.");

        }
        catch(ClientRegistrationException e)
        {
            Assert.assertTrue(e.getMessage().contains("Redirect URIs in the payload should match or be a subset of Redirect URIs in the [software_statement]."));
        }

    }

    /**
     * This method tests the functionality of using common redirect URIs and JWKS URI from request payload, software_statement and respective software_* fields.
     *
     */
    @Test
    public void testCommonRedirectUrisErrorPayload()
    {
        DynamicClient client = getDynamicClient();
        OpenBankingPlugin plugin = new OpenBankingPlugin();

        String clientName = "testCommonRedirectUri";
        JwtClaims requestClaims = populateClaims(clientName, REDIRECT_URIS_1, JWKS_1);
        setSoftwareRedirectUriJwksUri(requestClaims, REDIRECT_URIS_3, JWKS_1);

        JwtClaims softwareStatementClaims = populateClaims(clientName, REDIRECT_URIS_1, JWKS_1);
        setSoftwareRedirectUriJwksUri(softwareStatementClaims, REDIRECT_URIS_2, JWKS_1);

        try
        {
            claimTranslator.processClaims(client, softwareStatementClaims);
            claimTranslator.processRequestJwtClaims(client, requestClaims, softwareStatementClaims);
            Assert.fail("Expected a ClientRegistrationException due to unavailability of common redirect uris.");

        }
        catch(ClientRegistrationException e)
        {
            Assert.assertTrue(e.getMessage().contains("The [redirect_uris] and [software_redirect_uris] values must be the same."));
        }

    }


    /**
     * This method tests the functionality of selecting a JWKS URI from the software statement JWT
     * while ignoring the JWKS URIs provided in the request JWT
     *
     * In this method the input payload has the following configuration:
     * jwks_uri - https://localhost:9031/pf/JWKS
     * software_jwks_endpoint - https://localhostinvalid:9031/pf/JWKS
     *
     * Claims in software_statement
     * jwks_uri - https://localhost:9031/pf/JWKS
     * software_jwks_endpoint - https://localhostinvalid:9031/pf/JWKS
     *
     */
    @Test
    public void testCommonJwksUri()
    {
        DynamicClient client = getDynamicClient();
        ((DynamicOAuthClient)client).setRequireSignedRequests(false);

        String clientName = "testCommonRedirectUri";
        JwtClaims requestClaims = populateClaims(clientName, REDIRECT_URIS_1, JWKS_1);
        requestClaims.setClaim("token_endpoint_auth_method", "private_key_jwt");

        setSoftwareRedirectUriJwksUri(requestClaims, REDIRECT_URIS_1, JWKS_2);

        JwtClaims softwareStatementClaims = populateClaims(clientName, null, JWKS_1);
        setSoftwareRedirectUriJwksUri(softwareStatementClaims, null, null);
        try
        {
            claimTranslator.processClaims(client, softwareStatementClaims);
            claimTranslator.processRequestJwtClaims(client, requestClaims, softwareStatementClaims);
        }
        catch(ClientRegistrationException e)
        {
            Assert.fail("Expected a common JWKS URI but not obtained.");
        }
        Assert.assertTrue(client.getJwksUrl().equals(JWKS_1));

    }

    /**
     * This method tests the functionality of selecting a JWKS URI from the software statement JWT
     * while ignoring the JWKS URIs provided in the request JWT.
     *
     * In this method the input payload has the following configuration:
     * jwks_uri - https://localhost:9031/pf/JWKS
     * software_jwks_endpoint - https://localhostinvalid:9031/pf/JWKS
     *
     * Claims in software_statement
     * jwks_uri - https://localhost:9031/pf/JWKS
     * software_jwks_endpoint - https://localhost:9031/pf/JWKS
     *
     * Since there is no common JWKS URI in the input payload claims, there shall be no common JWKS URI.
     *
     */
    @Test
    public void testNoCommonJwksUri()
    {
        DynamicClient client = getDynamicClient();

        String clientName = "testNoCommonRedirectUri";
        JwtClaims requestClaims = populateClaims(clientName, REDIRECT_URIS_1, JWKS_1);
        setSoftwareRedirectUriJwksUri(requestClaims, REDIRECT_URIS_1, JWKS_2);

        JwtClaims softwareStatementClaims = populateClaims(clientName, null, JWKS_1);
        setSoftwareRedirectUriJwksUri(softwareStatementClaims, null, JWKS_2);

        try
        {
            claimTranslator.processClaims(client, softwareStatementClaims);
            claimTranslator.processRequestJwtClaims(client, requestClaims, softwareStatementClaims);

            Assert.fail("Expecting a ClientRegistrationException for not having common redirect URIs.");

        }
        catch(ClientRegistrationException e)
        {
            Assert.assertTrue(e.getMessage().contains("Unable to find common JWKS URI in the payload."));
        }

    }

    /**
     * This method tests the functionality of selecting a JWKS URI
     * for a Client with TLS Authentication and require signed requests.
     *
     * In this method the input payload has the following configuration:
     * jwks_uri - https://localhost:9031/pf/JWKS
     * software_jwks_endpoint - https://localhostinvalid:9031/pf/JWKS
     * token_endpoint_auth_method - tls_client_auth
     * tls_client_auth_subject_dn - cn=test
     *
     * Claims in software_statement
     * jwks_uri - https://localhost:9031/pf/JWKS
     * software_jwks_endpoint - https://localhostinvalid:9031/pf/JWKS
     *
     */
    @Test
    public void testRequireSignedRequestsJwksUri()
    {
        DynamicClient client = getDynamicClient();
        ((DynamicOAuthClient)client).setRequireSignedRequests(true);

        String clientName = "testRequireSignedRequestsJwksUri";
        JwtClaims requestClaims = populateClaims(clientName, REDIRECT_URIS_1, JWKS_1);
        requestClaims.setClaim("token_endpoint_auth_method", "tls_client_auth");
        requestClaims.setClaim("tls_client_auth_subject_dn","cn=test");

        setSoftwareRedirectUriJwksUri(requestClaims, REDIRECT_URIS_1, JWKS_2);

        JwtClaims softwareStatementClaims = populateClaims(clientName, null, JWKS_1);
        setSoftwareRedirectUriJwksUri(softwareStatementClaims, null, null);
        try
        {
            claimTranslator.processClaims(client, softwareStatementClaims);
            claimTranslator.processRequestJwtClaims(client, requestClaims, softwareStatementClaims);
        }
        catch(ClientRegistrationException e)
        {
            Assert.fail("Expected a common JWKS URI but not obtained.");
        }
        Assert.assertTrue(client.getJwksUrl().equals(JWKS_1));
        Assert.assertTrue(client.getClientCertSubjectDn().equals("cn=test"));

    }


}
