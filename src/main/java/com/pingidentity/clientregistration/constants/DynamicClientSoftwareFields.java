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

public enum DynamicClientSoftwareFields
{
    SOFTWARE_CLIENT_NAME("software_client_name"),
    SOFTWARE_JWKS_ENDPOINT("software_jwks_endpoint"),
    SOFTWARE_JWKS_REVOKED_ENDPOINT("software_jwks_revoked_endpoint"),
    SOFTWARE_REDIRECT_URIS("software_redirect_uris");

    private String name;

    DynamicClientSoftwareFields(String softwareFieldName)
    {
        name = softwareFieldName;
    }

    public String getName()
    {
        return name;
    }
}

