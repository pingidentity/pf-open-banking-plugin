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

import com.pingidentity.sdk.oauth20.registration.ClientRegistrationException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.InvalidJwtSignatureException;
import org.junit.Assert;
import org.junit.Test;

import javax.ws.rs.core.Response;
import java.util.Collections;

public class JwksHandlerTest
{



    @Test
    public void testHandleInvalidJwtException()
    {
        JwksHandler jwksHandler = new JwksHandler(OpenBankingPluginTest.JWKS_1, null, true);
        try
        {
            jwksHandler.handleInvalidJwtException(new InvalidJwtException("Testing InvalidJwtException!", Collections.emptyList(), null));
            Assert.fail("Expecting ClientRegistrationException but wasn't thrown.");
        }
        catch(ClientRegistrationException e)
        {
            Assert.assertFalse(e.getMessage().contains(JwksHandler.SIGNATURE_VERIFICATION_FAILED_MESSAGE));
            Assert.assertTrue(e.getError() == ClientRegistrationException.ErrorCode.invalid_software_statement);
            Assert.assertTrue(e.getStatus() == Response.Status.BAD_REQUEST);
        }
    }

    @Test
    public void testHandleInvalidJwtExceptionSignature()
    {
        JwksHandler jwksHandler = new JwksHandler(OpenBankingPluginTest.JWKS_1, null, false);
        try
        {
            jwksHandler.handleInvalidJwtException(new InvalidJwtSignatureException(null,null));
        }
        catch(ClientRegistrationException e)
        {
            Assert.assertTrue(e.getMessage().contains(JwksHandler.SIGNATURE_VERIFICATION_FAILED_MESSAGE));
            Assert.assertTrue(e.getError() == ClientRegistrationException.ErrorCode.invalid_payload);
            Assert.assertTrue(e.getStatus() == Response.Status.BAD_REQUEST);
        }
    }
}
