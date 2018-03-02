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
import com.pingidentity.commonsvcs.api.Headers;
import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.PluginDescriptor;
import com.pingidentity.sdk.oauth20.registration.*;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.*;
import org.jose4j.keys.resolvers.VerificationKeyResolver;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.gui.CheckBoxFieldDescriptor;
import org.sourceid.saml20.adapter.gui.FieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.FieldValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;
import org.sourceid.saml20.adapter.gui.validation.impl.HttpURLValidator;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * This class implements the DynamicClientRegistrationPlugin to process a JWT input payload to
 * create an OAuth client.
 */
public class OpenBankingPlugin implements DynamicClientRegistrationPlugin
{
    private static final Log LOG = LogFactory.getLog(OpenBankingPlugin.class);

    private static final String TYPE = "Open Banking Software Assertion Validator";

    private static final String VERSION = "1.0";

    private static final String MEDIA_TYPE_JWT = "application/jwt";

    private String issuer;
    private JwksHandler jwksHandler;
    private String requestJwtAudience;
    private ClaimTranslator claimTranslator = new ClaimTranslator();
    private AlgorithmConstraints signatureConstraint = new AlgorithmConstraints(
            AlgorithmConstraints.ConstraintType.WHITELIST);
    private boolean enableRevokedJwksValidation;
    private Configuration configuration;

    /**
     * This method returns a plugin descriptor that describes the plugin in terms of field name, description and default value.
     * @return a plugin descriptor
     */
    @Override
    public PluginDescriptor getPluginDescriptor()
    {
        GuiConfigDescriptor guiDescriptor = new GuiConfigDescriptor("Complete the configuration below and enable this instance in your dynamic client registration policy to support Open Banking conformant client registration requests.");

        FieldDescriptor issuer = new TextFieldDescriptor(Constants.ISSUER_FIELD_NAME, "Value of the iss claim expected in the received software statement JWT.");
        issuer.addValidator(new RequiredFieldValidator());
        issuer.setDefaultValue(Constants.DEFAULT_OPEN_BANKING_ISSUER);
        guiDescriptor.addField(issuer);

        FieldDescriptor jwksEndpointUrl = new TextFieldDescriptor(Constants.JWKS_URL_FIELD_NAME, "A set of JSON Web Keys (JWKs) are downloaded from this endpoint and used for software statement JWT signature verification.");
        jwksEndpointUrl.addValidator(new RequiredFieldValidator());
        jwksEndpointUrl.setDefaultValue(Constants.DEFAULT_JWKS_URL_FIELD_NAME);
        guiDescriptor.addField(jwksEndpointUrl);

        FieldDescriptor requestJwtAudienceField = new TextFieldDescriptor(Constants.AUDIENCE_FIELD_NAME, "Value of the aud claim expected in the received request JWT.");
        guiDescriptor.addField(requestJwtAudienceField);

        FieldDescriptor ecAlgorithm = new CheckBoxFieldDescriptor(Constants.ECDSA_ALGORITHM_FIELD_NAME,
                                                                  "Allow the " + Constants.ECDSA_ALGORITHM_FIELD_NAME + " algorithm to be used for signatures.");
        //The Open Banking specification states that PS256 or ES256 algorithms should be used for signing.
        //ECDSA is the only algorithm type enabled by default as PingFederate supports RSA-PSS only when configured with a Hardware Security Module (HSM).
        ecAlgorithm.setDefaultValue(Boolean.TRUE.toString());
        guiDescriptor.addField(ecAlgorithm);

        FieldDescriptor pssAlgorithm = new CheckBoxFieldDescriptor(Constants.RSA_PSS_ALGORITHM_FIELD_NAME,
                                                                   "Allow the " + Constants.RSA_PSS_ALGORITHM_FIELD_NAME + "  algorithm to be used for signatures.");
        guiDescriptor.addField(pssAlgorithm);

        FieldDescriptor rsaAlgorithm = new CheckBoxFieldDescriptor(Constants.RSA_ALGORITHM_FIELD_NAME,
                                                                   "Allow the " + Constants.RSA_ALGORITHM_FIELD_NAME + "  algorithm to be used for signatures.");
        guiDescriptor.addField(rsaAlgorithm);

        FieldDescriptor enableRevokedJwksValidation = new CheckBoxFieldDescriptor(Constants.ENABLE_REVOKED_JWKS_VALIDATION_FIELD_NAME,
                                                                  "Consider revoked JWKS during signature validation.");
        enableRevokedJwksValidation.setDefaultValue(Boolean.TRUE.toString());
        guiDescriptor.addAdvancedField(enableRevokedJwksValidation);


        guiDescriptor.addValidator(configuration -> {

            Field jwksUrlField = configuration.getField(Constants.JWKS_URL_FIELD_NAME);
            String jwksUriValue = jwksUrlField.getValue();

            List<String> errors = new ArrayList<>();

            if (StringUtils.isBlank(jwksUriValue))
            {
                errors.add(Constants.JWKS_URL_FIELD_NAME + " is required to verify the request payload.");
            }
            else
            {
                FieldValidator httpURLValidator = new HttpURLValidator();
                httpURLValidator.validate(jwksUrlField);
            }

            if(!(configuration.getBooleanFieldValue(Constants.ECDSA_ALGORITHM_FIELD_NAME) ||
               configuration.getBooleanFieldValue(Constants.RSA_PSS_ALGORITHM_FIELD_NAME) ||
               configuration.getBooleanFieldValue(Constants.RSA_ALGORITHM_FIELD_NAME)))
            {
                errors.add("At least one of the signature algorithms should be selected.");
            }

            if (!errors.isEmpty())
            {
                throw new ValidationException(errors);
            }
        });

        DynamicClientRegistrationPluginDescriptor pluginDescriptor = new DynamicClientRegistrationPluginDescriptor(TYPE, this, guiDescriptor, VERSION);
        pluginDescriptor.setSupportsExtendedContract(false);

        return pluginDescriptor;
    }

    /**
     * This method processes the input request to populate values to the input PingFederate OAuth Client instance.
     *
     * @param request client registration request
     * @param response a response
     * @param dynamicClient a PingFederate OAuth Client instance populated with default values
     * @param inParameters additional parameters to process the plugin
     * @throws ClientRegistrationException For unsupported media type input
     */
    @Override
    public void processPlugin(HttpServletRequest request, HttpServletResponse response, DynamicClient dynamicClient, Map<String, Object> inParameters)
            throws ClientRegistrationException
    {
        String contentType = request.getHeader(Headers.CONTENT_TYPE);
        if (contentType != null && !contentType.toLowerCase().contains(MEDIA_TYPE_JWT))
        {
            throw new ClientRegistrationException(Response.Status.UNSUPPORTED_MEDIA_TYPE,
                    ClientRegistrationException.ErrorCode.invalid_payload, "This plugin only handles JWT request type.");
        }

        String pluginId = this.configuration.getId();
        String requestJwt = (String) inParameters.get(DynamicClientRegistrationPlugin.IN_PARAMETER_NAME_REQUEST_BODY);

        processJwt(dynamicClient, pluginId, requestJwt);

    }

    /**
     * This method processes the input JWT payload to populate values for input OAuth Client.
     *
     * @param dynamicClient a PingFederate OAuth Client instance populated with default values
     * @param pluginId plugin ID
     * @param requestJwt input JWT payload
     * @throws ClientRegistrationException a ClientRegistrationException when PingFederate is unable to process the input JWT.
     */
    private void processJwt(DynamicClient dynamicClient, String pluginId, String requestJwt) throws ClientRegistrationException
    {
        LOG.debug("Obtain claims from input JWT.");
        JwtClaims requestClaimsUnverified = claimTranslator.getClaimsWithoutSignatureVerification(requestJwt, false);
        LOG.debug("Successfully obtained claims from input JWT.");


        if(requestClaimsUnverified != null && requestClaimsUnverified.hasClaim(DynamicClientFields.SOFTWARE_STATEMENT.getName()))
        {
            String softwareStatement = (String) requestClaimsUnverified.getClaimValue(DynamicClientFields.SOFTWARE_STATEMENT.getName());
            LOG.debug("Obtain claims from software_statement JWT.");
            JwtClaims softwareStatementClaims = getVerifiedJwtClaims(pluginId, softwareStatement, true, jwksHandler, null);
            LOG.debug("Successfully obtained claims from software_statement JWT.");

            LOG.debug("Obtain claims from input JWT.");
            JwtClaims requestJwtVerifiedClaims = getVerifiedRequestJwtClaims(pluginId, requestJwt, softwareStatementClaims);
            LOG.debug("Successfully obtained claims input JWT.");


            LOG.debug("Processing claims from software_statement to create a client.");
            claimTranslator.processClaims(dynamicClient, softwareStatementClaims);
            LOG.debug(" Successfully processed claims from software_statement JWT.");

            LOG.debug("Obtain claims from input JWT to create a client.");
            claimTranslator.processRequestJwtClaims(dynamicClient, requestJwtVerifiedClaims);
            LOG.debug(" Successfully processed claims from input JWT.");

            String clientName = getClientName(dynamicClient, softwareStatementClaims);
            dynamicClient.setName(clientName);

        }
        else
        {
            throw new ClientRegistrationException(Response.Status.BAD_REQUEST, ClientRegistrationException.ErrorCode.invalid_payload,
                    "["+ DynamicClientFields.SOFTWARE_STATEMENT.getName()+"] is required.");
        }
    }

    /**
     * This method validates and verifies the request JWT.
     * The JWKS URI to verify the signature on request JWT is obtain from the software statement.
     *
     * @param pluginId the plugin Id
     * @param requestJwt input request payload JWT
     * @param softwareStatementClaims claims extracted form software statement
     * @return claims from the request JWT
     * @throws ClientRegistrationException if a JWKS URI was not provided
     */
    private JwtClaims getVerifiedRequestJwtClaims(String pluginId, String requestJwt, JwtClaims softwareStatementClaims)
            throws ClientRegistrationException
    {
        //Obtain the JWKS URI from the software statement to verify the signature on request JWT
        String softwareStatementJwksUri = claimTranslator.getJwksUri(softwareStatementClaims);
        String revokedJwksUri;
        try
        {
            revokedJwksUri = softwareStatementClaims.getStringClaimValue(DynamicClientSoftwareFields.SOFTWARE_JWKS_REVOKED_ENDPOINT.getName());
        }
        catch(MalformedClaimException e)
        {
            throw new ClientRegistrationException(Response.Status.BAD_REQUEST, ClientRegistrationException.ErrorCode.invalid_software_statement,
                                                  "Unable to obtain "+DynamicClientSoftwareFields.SOFTWARE_JWKS_REVOKED_ENDPOINT.getName()+" " +
                                                  "from ["+ DynamicClientFields.SOFTWARE_STATEMENT.getName()+"] to verify the request JWT signature.");
        }
        if(StringUtils.isEmpty(softwareStatementJwksUri))
        {
            throw new ClientRegistrationException(Response.Status.BAD_REQUEST, ClientRegistrationException.ErrorCode.invalid_software_statement,
                                                  "Unable to obtain JWKS URI from ["+ DynamicClientFields.SOFTWARE_STATEMENT.getName()+"] to verify the request JWT signature.");
        }
        JwksHandler requestJwksHandler = new JwksHandler(softwareStatementJwksUri, signatureConstraint, false);
        return getVerifiedJwtClaims(pluginId, requestJwt, false, requestJwksHandler, revokedJwksUri);
    }

    /**
     * This method generates the client name of pattern org_name:software_client_name:software_version:<client_id>
     *
     * @param dynamicClient a PingFederate OAuth Client
     * @param softwareStatementClaims Software statement claims obtained by translating the "software_statement"
     * @return a client name
     */
    private String getClientName(DynamicClient dynamicClient, JwtClaims softwareStatementClaims)
    {
        StringBuilder clientName = new StringBuilder();
        appendClaimValue(clientName, softwareStatementClaims, Constants.ORG_NAME);
        appendClaimValue(clientName, softwareStatementClaims, Constants.SOFTWARE_CLIENT_NAME);
        appendClaimValue(clientName, softwareStatementClaims, Constants.SOFTWARE_VERSION);
        clientName.append(dynamicClient.getClientId());

        return clientName.toString();
    }

    /**
     * This method appends individual values to client name.
     *
     * @param clientName partially generated client name
     * @param claims input claims
     * @param claimName the name of claim that will be used for client name creation
     */
    private void appendClaimValue(StringBuilder clientName, JwtClaims claims, String claimName)
    {
        Object claimValue =  claims.getClaimValue(claimName);
        if(claimValue != null)
        {
            clientName.append(claimValue);
            clientName.append(":");
        }
    }


    /**
     * This method returns all the claims upon verifying and translating the input JWT.
     *
     * @param pluginId the plugin Id
     * @param jwt input request JWT or software statement JWT
     * @param isSoftwareStatement whether the input JWT is a software statement.
     * @param softwareStatementRevokedJwksUri JWKS URI from software statement
     * @return JwtClaims
     * @throws ClientRegistrationException a ClientRegistrationException when PingFederate is unable to process the input JWT.
     */
    private JwtClaims getVerifiedJwtClaims(String pluginId, String jwt, boolean isSoftwareStatement,
                                           JwksHandler keyHandler, String softwareStatementRevokedJwksUri) throws ClientRegistrationException
    {
        JwtClaims jwtClaims = null;
        JwtContext jwtContext;

        try
        {
            // Validate the JWT
            VerificationKeyResolver resolver = keyHandler.createVerificationKeyResolver(jwt, softwareStatementRevokedJwksUri,
                                                                                        enableRevokedJwksValidation);
            if (resolver == null || StringUtils.isBlank(issuer))
            {
                String description = "[" + pluginId + "] policy plugin is not configured correctly. Please revisit the configuration.";
                LOG.error(description);
                throw new ClientRegistrationException(Response.Status.INTERNAL_SERVER_ERROR, ClientRegistrationException.ErrorCode.internal_error, "Invalid configuration");
            }

            JwtConsumer jwtConsumer;
            if(isSoftwareStatement)
            {
                LOG.debug("Validating software_statement.");
                jwtConsumer = validateSoftwareStatement(resolver);
            }
            else
            {
                LOG.debug("Validating input JWT.");
                jwtConsumer = validateRequestJwt(resolver);
            }

            jwtContext = jwtConsumer.process(jwt);
            LOG.debug("Validating successful.");

            //Process claims in the client metadata request
            jwtClaims = jwtContext.getJwtClaims();
        }
        catch (InvalidJwtException e)
        {
            keyHandler.handleInvalidJwtException(e);
        }

        return jwtClaims;
    }

    /**
     * This method verifies the signature and issuer of the software statement
     * @param resolver a key resolver for software statement JWT JWKS URI
     * @return a JWT consumer
     */
    private JwtConsumer validateSoftwareStatement(VerificationKeyResolver resolver)
    {
        return new JwtConsumerBuilder()
                        .setExpectedIssuer(true, issuer)// Ensure expected issuer
                        .setVerificationKeyResolver(resolver) // Verify the signature
                        .setJwsAlgorithmConstraints(signatureConstraint)// Restrict the list of allowed signing algorithms
                        .build();
    }

    /**
     * This method verifies the signature and issuer of the request JWT
     * @param resolver  a key resolver for request JWT JWKS URI
     * @return a JWT consumer
     */
    private JwtConsumer validateRequestJwt(VerificationKeyResolver resolver)
    {
        return new JwtConsumerBuilder()
                .setRequireExpirationTime() //requires expiration time
                .setRequireIssuedAt()
                .setRequireJwtId()
                .setExpectedAudience(requestJwtAudience != null && StringUtils.isNotEmpty(requestJwtAudience), requestJwtAudience)
                .setVerificationKeyResolver(resolver) // Verify the signature
                .setJwsAlgorithmConstraints(signatureConstraint)// Restrict the list of allowed signing algorithms
                .build();
    }

    /**
     * This method uses whitelisted signature algorithms to populate a signing algorithm constraint.
     *
     * @param configuration the plugin configuration
     */
    private void populateSignatureConstraint(Configuration configuration)
    {
        String[] algorithms = new String[0];

        if(configuration.getBooleanFieldValue(Constants.ECDSA_ALGORITHM_FIELD_NAME))
        {
            algorithms = (String[]) ArrayUtils.addAll(algorithms, new String[] {AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256,
                                                        AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384,
                                                        AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512});
        }

        if(configuration.getBooleanFieldValue(Constants.RSA_PSS_ALGORITHM_FIELD_NAME))
        {
            algorithms = (String[])ArrayUtils.addAll(algorithms, new String[] {AlgorithmIdentifiers.RSA_PSS_USING_SHA256,
                                                        AlgorithmIdentifiers.RSA_PSS_USING_SHA384,
                                                        AlgorithmIdentifiers.RSA_PSS_USING_SHA512});
        }

        if(configuration.getBooleanFieldValue(Constants.RSA_ALGORITHM_FIELD_NAME))
        {
            {
                algorithms = (String[]) ArrayUtils.addAll(algorithms, new String[] {AlgorithmIdentifiers.RSA_USING_SHA256,
                                                            AlgorithmIdentifiers.RSA_USING_SHA384,
                                                            AlgorithmIdentifiers.RSA_USING_SHA512});
            }
        }

        this.signatureConstraint = new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST,
                                                            algorithms);

    }

    /**
     * This method is called by the PingFederate server to push configuration values provided by the administrator through the administration console or API calls.
     *
     * @param configuration The plugin configuration
     */
    @Override
    public void configure(Configuration configuration)
    {
        this.configuration = configuration;
        this.issuer = configuration.getFieldValue(Constants.ISSUER_FIELD_NAME);
        this.requestJwtAudience = configuration.getFieldValue(Constants.AUDIENCE_FIELD_NAME);
        this.enableRevokedJwksValidation = configuration.getBooleanFieldValue(Constants.ENABLE_REVOKED_JWKS_VALIDATION_FIELD_NAME);
        String jwksUrl = configuration.getFieldValue(Constants.JWKS_URL_FIELD_NAME);
        populateSignatureConstraint(configuration);

        // This handler processes the JWKS URL for verifying the signature of software statements
        this.jwksHandler = new JwksHandler(jwksUrl, signatureConstraint, true);

    }
}