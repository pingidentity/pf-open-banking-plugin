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

import com.pingidentity.access.TrustedCAAccessor;
import com.pingidentity.clientregistration.constants.DynamicClientSoftwareFields;
import com.pingidentity.sdk.oauth20.registration.ClientRegistrationException;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.jose4j.http.Get;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.*;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UnresolvableKeyException;

import javax.ws.rs.core.Response;
import java.io.IOException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * This class handles downloading JWKs and verifying JWT signature. It also handles the revoked JWKS URIs.
 */
class JwksHandler
{
    private static final long JWKS_CACHE_DURATION = 3600;
    private String jwksUrl;
    private boolean isSoftwareStatement;
    private AlgorithmConstraints signatureConstraint;
    static final String SIGNATURE_VERIFICATION_FAILED_MESSAGE = "Signature verification failed. ";

    private static final Log LOG = LogFactory.getLog(JwksHandler.class);


    JwksHandler(String jwksUrl, AlgorithmConstraints signatureConstraint, boolean isSoftwareStatement)
    {
        this.jwksUrl = jwksUrl;
        this.signatureConstraint = signatureConstraint;
        this.isSoftwareStatement = isSoftwareStatement;
    }

    /**
     * This method obtains a resolver using the JWKS URI.
     *
     * @param requestJwt input request JWT
     * @param softwareStatementRevokedJwksUri revoked JWKS URI from software statement
     * @return a verification resolver
     * @throws ClientRegistrationException when the software statement JWT was signed by a revoked JWK
     */
    VerificationKeyResolver createVerificationKeyResolver(String requestJwt, String softwareStatementRevokedJwksUri,
                                                          boolean enableJwksValidation) throws ClientRegistrationException
    {
        VerificationKeyResolver resolver = null;

        // Revoked JWKS URI is only applicable for input request JWT
        if(enableJwksValidation && !isSoftwareStatement)
        {
            LOG.debug("Validate that the JWT was not signed by a key from revoked JWKS.");
            handleRevokedJwks(requestJwt, softwareStatementRevokedJwksUri);
            LOG.debug("Validation successful, request not signed by a key from revoked JWKS.");
        }
        if (StringUtils.isNotEmpty(jwksUrl))
        {
            HttpsJwks httpsJwks = getHttpsJwks(jwksUrl);
            resolver = new HttpsJwksVerificationKeyResolver(httpsJwks);
        }

        return resolver;
    }

    /**
     * This method downloads the JWKs from the input JWKS URI
     *
     * @param jwksEndpoint input JWKS URI
     * @return HttpsJwks, that allows us to access parsed JWKs
     */
    private HttpsJwks getHttpsJwks(String jwksEndpoint)
    {
        HttpsJwks httpsJwks = new HttpsJwks(jwksEndpoint);
        httpsJwks.setSimpleHttpGet(getSimpleGet());
        httpsJwks.setRetainCacheOnErrorDuration(JWKS_CACHE_DURATION);
        return httpsJwks;
    }

    /**
     * This method retrieves the software_jwks_revoked_endpoint claim and uses to check
     * if the input software_statement can be verified using a revoked JWK.
     *
     * @param jwt request Jwt
     * @param jwksRevokedEndpoint revoked JWKS URI from software statement
     * @throws ClientRegistrationException if the software statement can be verified with a revoked JWKs.
     */
    private void handleRevokedJwks(String jwt, String jwksRevokedEndpoint)
            throws ClientRegistrationException
    {
        if(StringUtils.isBlank(jwksRevokedEndpoint))
        {
            return;
        }

        try
        {
            HttpsJwks revokedHttpJwks = getHttpsJwks(jwksRevokedEndpoint);

            List<JsonWebKey> revokedJwks = revokedHttpJwks.getJsonWebKeys();

            JwksVerificationKeyResolver jwksResolver = new JwksVerificationKeyResolver(revokedJwks);

            //Use the Revoked JWKs to verify the JWT
            jwksResolver.setDisambiguateWithVerifySignature(true);
            final JwtConsumerBuilder jwtConsumerBuilder = new JwtConsumerBuilder()
                    .setSkipVerificationKeyResolutionOnNone()
                    .setSkipDefaultAudienceValidation()
                    .setVerificationKeyResolver(jwksResolver)
                    .setJwsAlgorithmConstraints(signatureConstraint);

            JwtConsumer jwtConsumer = jwtConsumerBuilder.build();
            jwtConsumer.process(jwt);

            // If the signature verification was successful, the JWT was signed by a revoked JWKS
            throw new ClientRegistrationException(Response.Status.BAD_REQUEST, ClientRegistrationException.ErrorCode.invalid_payload,
                                                  "The input JWT is signed by a key in revoked JWKS.");


        }
        catch(InvalidJwtException e)
        {
            // If an exception was thrown due to signature verification using revoked JWKs, we do not want to escalate it.
            if(!isSignatureVerificationFailure(e))
            {
                handleInvalidJwtException(e);
            }
        }
        catch (IOException | JoseException e)
        {
            throw new ClientRegistrationException(Response.Status.BAD_REQUEST, ClientRegistrationException.ErrorCode.invalid_payload,
                                                  "Unable to download and parse ["+DynamicClientSoftwareFields.SOFTWARE_JWKS_REVOKED_ENDPOINT.getName()+"].");
        }


    }

    /**
     * This method accepts an InvalidJwtException and generates a ClientRegistrationException
     * with appropriate message and error code.
     *
     * @param e an InvalidJwtException
     * @throws ClientRegistrationException a ClientRegistrationException is thrown with appropriate error message.
     */
    void handleInvalidJwtException(InvalidJwtException e)
            throws ClientRegistrationException
    {
        String description;
        ClientRegistrationException.ErrorCode errorCode;

        if(isSignatureVerificationFailure(e))
        {
            description = SIGNATURE_VERIFICATION_FAILED_MESSAGE;
        }
        else
        {
            description = "Invalid JWT, " + e.getMessage();
        }

        if(isSoftwareStatement)
        {
            errorCode = ClientRegistrationException.ErrorCode.invalid_software_statement;
        }
        else
        {
            errorCode = ClientRegistrationException.ErrorCode.invalid_payload;
        }

        throw new ClientRegistrationException(Response.Status.BAD_REQUEST, errorCode, description);
    }

    /**
     * This method checks if the input exception was thrown due failure of signature verification.
     *
     * @param e input InvalidJwtException
     * @return TRUE if the input exception was thrown due failure of signature verification.
     */
    private boolean isSignatureVerificationFailure(InvalidJwtException e)
    {
        return e != null && (e instanceof InvalidJwtSignatureException ||
                e.getCause() != null && e.getCause() instanceof UnresolvableKeyException);
    }

    /**
     * This method performs hostname verification for the configured JWKS URI.
     */
    private Get getSimpleGet()
    {
        Get get = new Get();
        final TrustedCAAccessor trustedCAAccessor = new TrustedCAAccessor();
        final Set<TrustAnchor> allTrustAnchors = trustedCAAccessor.getAllTrustAnchors();
        Collection<X509Certificate> trustedCertificates = new ArrayList<>();
        for (TrustAnchor ta : allTrustAnchors)
        {
            trustedCertificates.add(ta.getTrustedCert());
        }
        get.setHostnameVerifier(SSLConnectionSocketFactory.getDefaultHostnameVerifier());
        get.setTrustedCertificates(trustedCertificates);

        return get;
    }
}
