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

package com.pingidentity.clientregistration.constants;

import com.google.common.collect.Sets;
import com.pingidentity.sdk.oauth20.registration.DynamicClientFields;

import java.util.Set;

public class Constants
{
    public static final String ISSUER_FIELD_NAME = "Issuer";
    public static final String JWKS_URL_FIELD_NAME = "JWKS URL";
    public static final String AUDIENCE_FIELD_NAME = "Audience";
    public static final String ECDSA_ALGORITHM_FIELD_NAME = "ECDSA";
    public static final String RSA_PSS_ALGORITHM_FIELD_NAME = "RSA-PSS";
    public static final String RSA_ALGORITHM_FIELD_NAME = "RSA";
    public static final String ENABLE_REVOKED_JWKS_VALIDATION_FIELD_NAME = "Revoked JWKS validation";

    public static final String DEFAULT_JWKS_URL_FIELD_NAME = "https://jwks.openbanking.org.uk/org_id/software_id.jkws";
    public static final String DEFAULT_OPEN_BANKING_ISSUER = "OpenBanking Ltd";
    public static final String ORG_NAME = "org_name";
    public static final String SOFTWARE_CLIENT_NAME = "software_client_name";
    public static final String SOFTWARE_VERSION = "software_version";
    public static final String APPLICATION_TYPE = "application_type";


    public static final Set<DynamicClientFields> CLAIMS_FROM_REQUEST_JWT = Sets.newHashSet(DynamicClientFields.REDIRECT_URIS,
                                                                                           DynamicClientFields.TOKEN_ENDPOINT_AUTH_METHOD,
                                                                                           DynamicClientFields.GRANT_TYPES,
                                                                                           DynamicClientFields.RESPONSE_TYPES,
                                                                                           DynamicClientFields.ID_TOKEN_SIGNED_RESPONSE_ALG,
                                                                                           DynamicClientFields.SCOPE,
                                                                                           DynamicClientFields.TLS_CLIENT_AUTH_SUBJECT_DN,
                                                                                           DynamicClientFields.ID_TOKEN_ENCRYPTED_RESPONSE_ALG,
                                                                                           DynamicClientFields.ID_TOKEN_ENCRYPTED_RESPONSE_ENC,
                                                                                           DynamicClientFields.REQUEST_OBJECT_SIGNING_ALG,
                                                                                           DynamicClientFields.TOKEN_ENDPOINT_AUTH_SIGNING_ALG,
                                                                                           DynamicClientFields.BACKCHANNEL_TOKEN_DELIVERY_MODE,
                                                                                           DynamicClientFields.BACKCHANNEL_CLIENT_NOTIFICATION_ENDPOINT,
                                                                                           DynamicClientFields.BACKCHANNEL_USER_CODE_PARAMETER,
                                                                                           DynamicClientFields.BACKCHANNEL_AUTHENTICATION_REQUEST_SIGNING_ALG,
                                                                                           DynamicClientFields.SUBJECT_TYPE,
                                                                                           DynamicClientFields.SECTOR_IDENTIFIER_URI,
                                                                                           DynamicClientFields.DPOP_BOUND_ACCESS_TOKENS,
                                                                                           DynamicClientFields.USERINFO_SIGNED_RESPONSE_ALG,
                                                                                           DynamicClientFields.USERINFO_ENCRYPTED_RESPONSE_ALG,
                                                                                           DynamicClientFields.USERINFO_ENCRYPTED_RESPONSE_ENC);

    public enum ApplicationType
    {
        WEB("web"),
        MOBILE("mobile");

        private String name;
        ApplicationType(String name)
        {
            this.name = name;
        }

        public String getName()
        {
            return name;
        }
    }
}