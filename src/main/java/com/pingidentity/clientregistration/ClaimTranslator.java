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
import com.pingidentity.sdk.oauth20.registration.ClientAuthType;
import com.pingidentity.sdk.oauth20.registration.ClientRegistrationException;
import com.pingidentity.sdk.oauth20.registration.ClientRegistrationException.ErrorCode;
import com.pingidentity.sdk.oauth20.registration.DynamicClient;
import com.pingidentity.sdk.oauth20.registration.DynamicClientFields;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;

import javax.ws.rs.core.Response;
import java.util.*;

import static javax.ws.rs.core.Response.Status.BAD_REQUEST;

/**
 * This class processes and translates claims to OAuth domain values.
 */
class ClaimTranslator
{
    private static final Log LOG = LogFactory.getLog(OpenBankingPlugin.class);

    /**
     * This method processes standard claims to populate values to a DynamicClient domain object.
     *
     * @param dynamicClient a domain object pre-populated with default values
     * @param claimName name of the claim that is being processed
     * @param jwtClaims all the claims from a JWT
     * @throws MalformedClaimException if an error occurred while parsing claims
     * @throws ClientRegistrationException if a claim value cannot be successfully translated to OAuth domain Object
     */
    private void processStandardClaim(DynamicClient dynamicClient, DynamicClientFields claimName, JwtClaims jwtClaims)
            throws MalformedClaimException, ClientRegistrationException
    {
        switch (claimName)
        {
            case REDIRECT_URIS:
                dynamicClient.setRedirectUris(getCommonRedirectUris(jwtClaims));
                break;

            case CLIENT_NAME:
                dynamicClient.setName(jwtClaims.getStringClaimValue(DynamicClientFields.CLIENT_NAME.getName()));
                break;
            case LOGO_URI:
                dynamicClient.setLogoUrl(jwtClaims.getStringClaimValue(DynamicClientFields.LOGO_URI.getName()));
                break;
            case JWKS_URI:
                dynamicClient.setJwksUrl(getJwksUri(jwtClaims));
                break;
            case JWKS:
                dynamicClient.setJwks(jwtClaims.getStringClaimValue(DynamicClientFields.JWKS.getName()));
                break;
            default:
                // do nothing: we only consider the OAuth specific claims obtained from request JWT and PingFederate proprietary attributes.
                // The remaining claims are treated as software or extended metadata.
                break;
        }
    }

    /**
     * This method populates standard OAuth claims from the Request JWT
     * @param dynamicClient a OAuth client
     * @param jwtClaims claims from the request JWT
     * @throws ClientRegistrationException when a required claim is not available or cannot be parsed
     */
    void processRequestJwtClaims(DynamicClient dynamicClient, JwtClaims jwtClaims)
            throws ClientRegistrationException
    {
        for (DynamicClientFields claimName: Constants.CLAIMS_FROM_REQUEST_JWT)
        {
            try
            {
                switch (claimName)
                {

                    case REDIRECT_URIS:
                        List<String> requestRedirectUris = getCommonRedirectUris(jwtClaims);
                        if (requestRedirectUris != null)
                        {
                            List<String> softwareRedirectUris = dynamicClient.getRedirectUris();
                            List<String> redirectUris = getCommonRedirectUris(requestRedirectUris, softwareRedirectUris);
                            dynamicClient.setRedirectUris(redirectUris);
                        }
                        break;
                    case TOKEN_ENDPOINT_AUTH_METHOD:
                        String tokenEndpointAuthMethod = jwtClaims.getStringClaimValue(DynamicClientFields.TOKEN_ENDPOINT_AUTH_METHOD.getName());
                        if (StringUtils.isEmpty(tokenEndpointAuthMethod))
                        {
                            throw new ClientRegistrationException(BAD_REQUEST,
                                                                  ErrorCode.invalid_payload,
                                                                  " A [" + DynamicClientFields.TOKEN_ENDPOINT_AUTH_METHOD.getName() + "] is required.");
                        }

                        dynamicClient.setClientAuthenticationType(tokenEndpointAuthMethod);
                        if (tokenEndpointAuthMethod.equalsIgnoreCase(ClientAuthType.client_secret_basic.toString()) ||
                            tokenEndpointAuthMethod.equalsIgnoreCase(ClientAuthType.client_secret_post.toString()))
                        {
                            dynamicClient.generateSecret(22);
                        }

                        if (!tokenEndpointAuthMethod.equalsIgnoreCase(ClientAuthType.private_key_jwt.toString()))
                        {
                            dynamicClient.setJwksUrl(null);
                        }
                        break;

                    case GRANT_TYPES:
                        List<String> grantTypes = getStringListClaimValue(jwtClaims, DynamicClientFields.GRANT_TYPES.getName());
                        if (grantTypes != null)
                        {
                            dynamicClient.setGrantTypes(new HashSet<>(grantTypes));
                        }
                        break;

                    case RESPONSE_TYPES:
                        dynamicClient.setRestrictedResponseTypes(getStringListClaimValue(jwtClaims, DynamicClientFields.RESPONSE_TYPES.getName()));
                        break;

                    case ID_TOKEN_SIGNED_RESPONSE_ALG:
                        dynamicClient.setIdTokenSigningAlgorithm(jwtClaims.getStringClaimValue(DynamicClientFields.ID_TOKEN_SIGNED_RESPONSE_ALG.getName()));
                        break;

                    case SCOPE:
                        String scopeClaim = jwtClaims.getStringClaimValue(DynamicClientFields.SCOPE.getName());
                        if(StringUtils.isNotEmpty(scopeClaim))
                        {
                            dynamicClient.setScopes(new ArrayList<>(Arrays.asList(scopeClaim.split(" "))));
                        }
                        break;

                    case TLS_CLIENT_AUTH_SUBJECT_DN:
                        dynamicClient.setClientCertSubjectDn(jwtClaims.getStringClaimValue(DynamicClientFields.TLS_CLIENT_AUTH_SUBJECT_DN.getName()));
                        break;

                    default:
                        //Do nothing: Rest of the claims has been extracted by software statement claims
                        break;
                }

                //for non-standard claims
                String applicationTypeClaim = jwtClaims.getStringClaimValue(Constants.APPLICATION_TYPE);
                if(StringUtils.isEmpty(applicationTypeClaim))
                {
                    throw new ClientRegistrationException(BAD_REQUEST,
                                                          ErrorCode.invalid_payload,
                                                          "["+Constants.APPLICATION_TYPE+"] is required");
                }
                else if(!Constants.ApplicationType.WEB.getName().equalsIgnoreCase(applicationTypeClaim))
                {
                    throw new ClientRegistrationException(BAD_REQUEST,
                                                          ErrorCode.invalid_payload,
                                                          "Unsupported ["+Constants.APPLICATION_TYPE+"] " + applicationTypeClaim);
                }
            }
            catch (MalformedClaimException e)
            {
                throw new ClientRegistrationException(BAD_REQUEST,
                                                      ErrorCode.invalid_payload,
                                                      e.getMessage());
            }
        }
    }

    /**
     * This method processes an extended client metadata and adds it to a DynamicClient domain object.
     *
     * @param dynamicClient a DynamicClient domain object
     * @param claimName name of the extended claim
     * @param jwtClaims all the claims from a JWT
     * @throws MalformedClaimException if a claim value cannot be parsed
     */
    private void processExtendedClaims(DynamicClient dynamicClient, String claimName, JwtClaims jwtClaims)
            throws MalformedClaimException
    {
        Object claimValue = jwtClaims.getClaimValue(claimName);
        if (claimValue != null)
        {
            if (claimValue instanceof List)
            {
                List<String> stringListClaimValue = jwtClaims.getStringListClaimValue(claimName);
                DynamicClient.Status status = dynamicClient.addClientMetadataValues(claimName, stringListClaimValue);
                if (!status.equals(DynamicClient.Status.SUCCESS))
                {
                    LOG.error("claim [" + claimName + "] was not added to the client object with the status of [" + status + "]");
                }
            }
            else if (claimValue instanceof String)
            {
                String stringClaimValue = jwtClaims.getStringClaimValue(claimName);
                DynamicClient.Status status = dynamicClient.addClientMetadataValues(claimName, Collections.singletonList(stringClaimValue));
                if (!status.equals(DynamicClient.Status.SUCCESS))
                {
                    LOG.error("claim [" + claimName + "] was not added to the client object with the status of [" + status + "]");
                }
            }
            else
            {
                throw new MalformedClaimException("claim [" + claimName + "] value is not supported.");
            }
        }
    }

    /**
     * This method processes Open Banking specific software claims in client metadata.
     *
     * @param dynamicClient a DynamicClient domain object
     * @param jwtClaims all the claims from a JWT
     */
    private void processSoftwareClaims(DynamicClient dynamicClient, DynamicClientSoftwareFields claimName, JwtClaims jwtClaims)
        throws ClientRegistrationException
    {
        switch (claimName) {
            case SOFTWARE_REDIRECT_URIS:
                List<String> clientRedirectUris = dynamicClient.getRedirectUris();
                if(clientRedirectUris != null && clientRedirectUris.isEmpty())
                {
                    List<String> redirectUris = getCommonRedirectUris(jwtClaims);
                    dynamicClient.setRedirectUris(redirectUris);
                }
                break;
            case SOFTWARE_JWKS_ENDPOINT:
                String clientJwksUri = dynamicClient.getJwksUrl();
                if(StringUtils.isEmpty(clientJwksUri))
                {
                    String jwksUri = getJwksUri(jwtClaims);
                    dynamicClient.setJwksUrl(jwksUri);
                }
                break;
            default:
                //do nothing: we only consider the OAuth spec and PF proprietary attributes
                // and the rest are treated as extended metadata
                break;
        }
    }

    /**
     * This method processes claims in client metadata.
     *
     * @param dynamicClient a PingFederate OAuth Client
     * @param jwtClaims all the claims from a JWT
     * @throws ClientRegistrationException if a claim value cannot be successfully translated to OAuth client
     */
    void processClaims(DynamicClient dynamicClient, JwtClaims jwtClaims)
            throws ClientRegistrationException
    {
        //Process individual JWT claims
        Collection<String> claimNames = jwtClaims.getClaimNames();
        Set<String> standardClaims = getStandardClaims();
        Set<String> softwareClaims = getSoftwareClaims();
        for (String claimName : claimNames)
        {
            try
            {
                if (standardClaims.contains(claimName))
                {
                    processStandardClaim(dynamicClient, DynamicClientFields.valueOf(claimName.toUpperCase()), jwtClaims);
                }
                else if(softwareClaims.contains(claimName))
                {
                    processSoftwareClaims(dynamicClient, DynamicClientSoftwareFields.valueOf(claimName.toUpperCase()), jwtClaims);
                }
                else if (dynamicClient.getClientMetadataKeys().contains(claimName))
                {
                    processExtendedClaims(dynamicClient, claimName, jwtClaims);
                }
                else
                {
                    LOG.debug("claim [" + claimName + "] is not a supported client metadata");
                }
            }
            catch (MalformedClaimException e)
            {
                LOG.error("claim [" + claimName + "] was not added to the client object due to a data conversion error.");
                LOG.debug(e.getMessage());
            }
        }
    }

    /**
     *
     * This method obtains a list of redirect URIs commonly present between the "redirect_uris" and "software_redirect_uris" claims.
     *
     * @param jwtClaims all the claims from a JWT
     * @return a list of common redirect URIs
     * @throws ClientRegistrationException if no common URIs are available
     */
    private List<String> getCommonRedirectUris(JwtClaims jwtClaims)
            throws ClientRegistrationException
    {
        String softwareRedirectUriName = DynamicClientSoftwareFields.SOFTWARE_REDIRECT_URIS.getName();
        String redirectUriName = DynamicClientFields.REDIRECT_URIS.getName();
        List<String> redirectUris = jwtClaims.hasClaim(redirectUriName)? getStringListClaimValue(jwtClaims, redirectUriName): null;
        List<String> softwareRedirectUris = jwtClaims.hasClaim(softwareRedirectUriName)? getStringListClaimValue(jwtClaims, softwareRedirectUriName): null;

        return getCommonUris(redirectUris, softwareRedirectUris);
    }

    /**
     * This method accepts 2 lists of URIs, if neither of the input lists are NULL,
     * a list of common URIs is returned. If one of the inputs is NULL, then the other is returned.
     *
     * @param redirectUris Redirect URIs
     * @param softwareRedirectUris Redirect URIs from software metadata
     * @return a list of common redirect URIs
     * @throws ClientRegistrationException if no common URIs are available
     */
    private List<String> getCommonUris(List<String> redirectUris, List<String> softwareRedirectUris)
            throws ClientRegistrationException
    {
        List<String> commonUri;
        // Redirect URI should not be empty
        if(redirectUris == null)
        {
            return softwareRedirectUris;
        }
        else if(softwareRedirectUris == null)
        {
            return redirectUris;
        }
        else
        {
            commonUri = getCommonRedirectUris(redirectUris, softwareRedirectUris);
            if(commonUri.size() != softwareRedirectUris.size() || commonUri.size() != redirectUris.size())
            {
                throw new ClientRegistrationException(BAD_REQUEST,
                                                      ErrorCode.invalid_redirect_uri,
                                                      "The ["+DynamicClientFields.REDIRECT_URIS.getName()+"] and ["+ DynamicClientSoftwareFields.SOFTWARE_REDIRECT_URIS.getName()
                                                      +"] values must be the same.");
            }
        }

        return commonUri;
    }

    /**
     * This method accepts 2 lists of URIs and returns a list of common URIs.
     *
     * @param redirectUris Redirect URIs
     * @param softwareRedirectUris Redirect URIs from software metadata or software statement.
     * @return a list of common URIs
     * @throws ClientRegistrationException if no common URIs are present
     */
    private List<String> getCommonRedirectUris(List<String> redirectUris, List<String> softwareRedirectUris)
            throws ClientRegistrationException
    {
        List<String> commonUri = new ArrayList<>();
        if(redirectUris != null && softwareRedirectUris != null)
        {
            for (String redirectUri : redirectUris)
            {
                for (String softwareRedirectUri : softwareRedirectUris)
                {
                    if (redirectUri.equals(softwareRedirectUri))
                    {
                        commonUri.add(redirectUri);
                        break;
                    }
                }
            }

            if(!redirectUris.isEmpty() && !softwareRedirectUris.isEmpty() && commonUri.isEmpty())
            {
                throw new ClientRegistrationException(BAD_REQUEST,
                                                      ErrorCode.invalid_redirect_uri,
                                                      "Redirect URIs in the payload should match or be a subset of Redirect URIs in the ["+ DynamicClientFields.SOFTWARE_STATEMENT.getName()+"].");
            }
        }
        return commonUri;
    }

    /**
     * This method obtains "jwks_uri" and "software_jwks_endpoint" claims. If values exist,
     * they should be comparable to each other.
     *
     * @param jwtClaims all the claims from a JWT
     * @return a JWKS URI
     * @throws ClientRegistrationException if values for "jwks_uri" and "software_jwks_endpoint" claims exist and do not match
     */
    String getJwksUri(JwtClaims jwtClaims)
            throws ClientRegistrationException
    {
        String commonJwKsUri;
        String jwksUriName = DynamicClientFields.JWKS_URI.getName();
        String softwareJwksUriName = DynamicClientSoftwareFields.SOFTWARE_JWKS_ENDPOINT.getName();
        String jwksUri = jwtClaims.hasClaim(jwksUriName)? getStringClaimValue(jwtClaims, jwksUriName): null;
        String softwareJwksUri = jwtClaims.hasClaim(softwareJwksUriName)? getStringClaimValue(jwtClaims, softwareJwksUriName): null;
        commonJwKsUri = getJwksUri(jwksUri, softwareJwksUri);

        return commonJwKsUri;
    }

    /**
     * This method returns a value for JWKS URI. If either of the input URIs is NULL, then the other
     * input URI is returned. Otherwise, if the values match, it is returned as JWKS URI.
     *
     * @param jwksUri the JWKS URI
     * @param softwareJwksUri JWKS URI from software metadata or software statement
     * @return a JWKS URI
     */
    private String getJwksUri(String jwksUri, String softwareJwksUri)
            throws ClientRegistrationException
    {
        if(jwksUri == null)
        {
            return softwareJwksUri;
        }
        else if(softwareJwksUri == null)
        {
            return jwksUri;
        }
        else if(jwksUri.equals(softwareJwksUri))
        {
            return jwksUri;
        }
        throw new ClientRegistrationException(BAD_REQUEST, ErrorCode.invalid_client_metadata, "Unable to find common JWKS URI in the payload.");
    }


    /**
     * This method returns claim value as a String of a claim with the name matching the input claimName.
     *
     * @param jwtClaims all the claims from a JWT
     * @param claimName name of the claim
     * @return a String claim value
     */
    private String getStringClaimValue(JwtClaims jwtClaims, String claimName)
    {
        try
        {
            return jwtClaims.getStringClaimValue(claimName);
        }
        catch(MalformedClaimException e)
        {
            LOG.error("claim [" + claimName + "] was not precessed due to a data conversion error.");
            LOG.debug(e.getMessage());
        }
        return null;
    }

    /**
     * This method returns claim value as a List of String of a claim with the name matching the input claimName.
     *
     * @param jwtClaims all the claims from a JWT
     * @param claimName name of the claim
     * @return a claim value list
     */
    private List<String> getStringListClaimValue(JwtClaims jwtClaims, String claimName)
    {
        try
        {
            if(jwtClaims.hasClaim(claimName))
            {
                if (jwtClaims.isClaimValueOfType(claimName, List.class))
                {
                    return jwtClaims.getStringListClaimValue(claimName);
                }
                else
                {
                    String value = jwtClaims.getStringClaimValue(claimName);
                    return Arrays.asList(value.split(" "));
                }
            }
        }
        catch(MalformedClaimException e)
        {
            LOG.error("claim [" + claimName + "] was not processed due to a data conversion error.");
            LOG.debug(e.getMessage());
        }
        return null;
    }

    /**
     * This method returns a set of standard metadata claim names.
     *
     * @return a set of standard metadata claim names.
     */
    private Set<String> getStandardClaims()
    {
        Set<String> values = new HashSet<>();
        for (DynamicClientFields c : DynamicClientFields.values())
        {
            values.add(c.getName());
        }
        return values;
    }

    /**
     * This method returns a set of software metadata claim names used by this plugin.
     *
     * @return a set of software metadata claim names
     */
    private Set<String> getSoftwareClaims()
    {
        Set<String> values = new HashSet<>();
        for (DynamicClientSoftwareFields c : DynamicClientSoftwareFields.values())
        {
            values.add(c.getName());
        }
        return values;
    }


    /**
     * This method obtains claims from the input JWT without validating the signature.
     *
     * @param jwt input JWT
     * @param isSoftwareStatement is the input JWT a software statement
     * @return JWT claims
     * @throws ClientRegistrationException if the input JWT cannot be parsed
     */
    JwtClaims getClaimsWithoutSignatureVerification(String jwt, boolean isSoftwareStatement) throws ClientRegistrationException
    {
        //get the claims without signature verification
        JwtConsumer validateSubJwtConsumer = new JwtConsumerBuilder()
                .setSkipSignatureVerification()
                .setSkipDefaultAudienceValidation()
                .build();
        JwtContext jwtContext;
        try
        {
             jwtContext = validateSubJwtConsumer.process(jwt);
        }
        catch (InvalidJwtException e)
        {
            ErrorCode errorCode = isSoftwareStatement? ErrorCode.invalid_software_statement: ClientRegistrationException.ErrorCode.invalid_payload;
            throw new ClientRegistrationException(Response.Status.BAD_REQUEST, errorCode, "Invalid JWT, "+e.getMessage());
        }


        return jwtContext.getJwtClaims();
    }
}