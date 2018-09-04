/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package com.wso2.jwt.token.builder;

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;



public class CustomJWTAccessTokenBuilder extends JWTTokenIssuer {


    private static final Log log = LogFactory.getLog(CustomJWTAccessTokenBuilder.class);

    public CustomJWTAccessTokenBuilder() throws IdentityOAuth2Exception {
    }


    /**
     * Create a JWT claim set according to the JWT format.
     *
     * @param authAuthzReqMessageContext Oauth authorization request message context.
     * @param tokenReqMessageContext     Token request message context.
     * @param consumerKey                Consumer key of the application.
     * @return JWT claim set.
     * @throws IdentityOAuth2Exception
     */
    @Override
    protected JWTClaimsSet createJWTClaimSet(OAuthAuthzReqMessageContext authAuthzReqMessageContext,
                                             OAuthTokenReqMessageContext tokenReqMessageContext,
                                             String consumerKey) throws IdentityOAuth2Exception {

        try {
            JWTClaimsSet jwtClaimsSet = super.createJWTClaimSet(authAuthzReqMessageContext, tokenReqMessageContext,
                    consumerKey);
            if (log.isDebugEnabled()) {
                log.debug("Standard claims are set from the super method");
            }
            // Set client-id claim.
            jwtClaimsSet.setClaim("client_id", consumerKey);
            if (log.isDebugEnabled()) {
                log.debug("Client-id claim is set to the JWTClaimSet and returning JWTClaimSet," +
                        " Client_id : " + consumerKey);
            }
            return jwtClaimsSet;
        } catch (IdentityOAuth2Exception e) {
            throw new IdentityOAuth2Exception("Error when setting client-id :" + consumerKey);
        }
    }

}
