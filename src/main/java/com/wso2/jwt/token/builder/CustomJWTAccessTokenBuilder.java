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

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.CustomClaimsCallbackHandler;

import java.security.Key;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;


public class CustomJWTAccessTokenBuilder extends JWTTokenIssuer {

    // Signature algorithms.
    private static final String NONE = "NONE";
    private static final String SHA256_WITH_RSA = "SHA256withRSA";
    private static final String SHA384_WITH_RSA = "SHA384withRSA";
    private static final String SHA512_WITH_RSA = "SHA512withRSA";
    private static final String SHA256_WITH_HMAC = "SHA256withHMAC";
    private static final String SHA384_WITH_HMAC = "SHA384withHMAC";
    private static final String SHA512_WITH_HMAC = "SHA512withHMAC";
    private static final String SHA256_WITH_EC = "SHA256withEC";
    private static final String SHA384_WITH_EC = "SHA384withEC";
    private static final String SHA512_WITH_EC = "SHA512withEC";

    private static final String KEY_STORE_EXTENSION = ".jks";
    private static final String AUTHORIZATION_PARTY = "azp";
    private static final String AUDIENCE = "aud";
    private static final String SCOPE = "scope";

    // To keep track of the expiry time provided in the original jwt assertion, when JWT grant type is used.
    private static final String EXPIRY_TIME_JWT = "EXPIRY_TIME_JWT";

    private static final Log log = LogFactory.getLog(CustomJWTAccessTokenBuilder.class);

    // We are keeping a private key map which will have private key for each tenant domain. We are keeping this as a
    // static Map since then we don't need to read the key from keystore every time.
    private static Map<Integer, Key> privateKeys = new ConcurrentHashMap<>();
    private Algorithm signatureAlgorithm = null;

    public CustomJWTAccessTokenBuilder() throws IdentityOAuth2Exception {
        if (log.isDebugEnabled()) {
            log.debug("JWT Access token builder is initiated");
        }

        OAuthServerConfiguration config = OAuthServerConfiguration.getInstance();

        // Map signature algorithm from identity.xml to nimbus format, this is a one time configuration.
        signatureAlgorithm = super.mapSignatureAlgorithm(config.getSignatureAlgorithm());
        //mapSignatureAlgorithm(config.getSignatureAlgorithm());
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

        // loading the stored application data
        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(consumerKey);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error while retrieving app information for clientId: " + consumerKey, e);
        }

        AuthenticatedUser user;
        long accessTokenLifeTimeInMillis;
        if (authAuthzReqMessageContext != null) {
            user = authAuthzReqMessageContext.getAuthorizationReqDTO().getUser();
            accessTokenLifeTimeInMillis =
                    getAccessTokenLifeTimeInMillis(authAuthzReqMessageContext, oAuthAppDO, consumerKey);
        } else {
            user = tokenReqMessageContext.getAuthorizedUser();
            accessTokenLifeTimeInMillis =
                    getAccessTokenLifeTimeInMillis(tokenReqMessageContext, oAuthAppDO, consumerKey);
        }
        String issuer = OAuth2Util.getIDTokenIssuer();
        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();

        // Set the default claims.
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        jwtClaimsSet.setIssuer(issuer);
        jwtClaimsSet.setSubject(user.getAuthenticatedSubjectIdentifier());
        jwtClaimsSet.setClaim(AUTHORIZATION_PARTY, consumerKey);
        jwtClaimsSet.setExpirationTime(new Date(curTimeInMillis + accessTokenLifeTimeInMillis));
        jwtClaimsSet.setIssueTime(new Date(curTimeInMillis));
        jwtClaimsSet.setJWTID(UUID.randomUUID().toString());
        jwtClaimsSet.setClaim("client_id", consumerKey);

        String scope = getScope(authAuthzReqMessageContext, tokenReqMessageContext);
        if (StringUtils.isNotEmpty(scope)) {
            jwtClaimsSet.setClaim(SCOPE, scope);
        }
        jwtClaimsSet.setExpirationTime(getExpiryTime(tokenReqMessageContext, jwtClaimsSet));

        // This is a spec (openid-connect-core-1_0:2.0) requirement for ID tokens. But we are keeping this in JWT
        // as well.
        jwtClaimsSet.setAudience(Collections.singletonList(consumerKey));
        // Handle custom claims
        if (authAuthzReqMessageContext != null) {
            handleCustomClaims(jwtClaimsSet, authAuthzReqMessageContext);
        } else {
            handleCustomClaims(jwtClaimsSet, tokenReqMessageContext);
        }

        return jwtClaimsSet;
    }

    /**
     * To get the scope of the token to be added to the JWT claims.
     *
     * @param authAuthzReqMessageContext Auth Request Message Context.
     * @param tokenReqMessageContext     Token Request Message Context.
     * @return scope of token.
     */
    private String getScope(OAuthAuthzReqMessageContext authAuthzReqMessageContext,
                            OAuthTokenReqMessageContext tokenReqMessageContext) throws IdentityOAuth2Exception {

        String[] scope;
        String scopeString = null;
        if (tokenReqMessageContext != null) {
            scope = tokenReqMessageContext.getScope();
        } else {
            scope = authAuthzReqMessageContext.getApprovedScope();
        }
        if (!ArrayUtils.isEmpty(scope)) {
            scopeString = OAuth2Util.buildScopeString(scope);
            if (log.isDebugEnabled()) {
                log.debug("Scope exist for the jwt access token with subject " + getAuthenticatedSubjectIdentifier(
                        authAuthzReqMessageContext, tokenReqMessageContext) + " and the scope is " + scopeString);
            }
        }
        return scopeString;
    }

    /**
     * To get authenticated subject identifier.
     *
     * @param authAuthzReqMessageContext Auth Request Message Context.
     * @param tokenReqMessageContext     Token request message context.
     * @return authenticated subject identifier.
     */
    private String getAuthenticatedSubjectIdentifier(OAuthAuthzReqMessageContext authAuthzReqMessageContext,
                                                     OAuthTokenReqMessageContext tokenReqMessageContext) throws IdentityOAuth2Exception {

        AuthenticatedUser authenticatedUser;
        if (authAuthzReqMessageContext != null) {
            authenticatedUser = authAuthzReqMessageContext.getAuthorizationReqDTO().getUser();
        } else {
            authenticatedUser = tokenReqMessageContext.getAuthorizedUser();
        }

        if (authenticatedUser == null) {
            throw new IdentityOAuth2Exception("Authenticated user is null for the request.");
        }
        return authenticatedUser.getAuthenticatedSubjectIdentifier();
    }


    /**
     * Get token validity period for the Self contained JWT Access Token. (For implicit grant)
     *
     * @param authzReqMessageContext
     * @param oAuthAppDO
     * @param consumerKey
     * @return
     * @throws IdentityOAuth2Exception
     */
    protected long getAccessTokenLifeTimeInMillis(OAuthAuthzReqMessageContext authzReqMessageContext,
                                                  OAuthAppDO oAuthAppDO,
                                                  String consumerKey) throws IdentityOAuth2Exception {
        long lifetimeInMillis = oAuthAppDO.getUserAccessTokenExpiryTime() * 1000;
        if (lifetimeInMillis == 0) {
            lifetimeInMillis = OAuthServerConfiguration.getInstance()
                    .getUserAccessTokenValidityPeriodInSeconds() * 1000;
            if (log.isDebugEnabled()) {
                log.debug("User access token time was 0ms. Setting default user access token lifetime : "
                        + lifetimeInMillis + "ms.");
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("JWT Self Signed Access Token Life time set to : " + lifetimeInMillis + "ms.");
        }
        return lifetimeInMillis;
    }

    /**
     * Get token validity period for the Self contained JWT Access Token.
     *
     * @param tokenReqMessageContext
     * @param oAuthAppDO
     * @param consumerKey
     * @return
     * @throws IdentityOAuth2Exception
     */
    protected long getAccessTokenLifeTimeInMillis(OAuthTokenReqMessageContext tokenReqMessageContext,
                                                  OAuthAppDO oAuthAppDO,
                                                  String consumerKey) throws IdentityOAuth2Exception {
        long lifetimeInMillis;
        boolean isUserAccessTokenType =
                isUserAccessTokenType(tokenReqMessageContext.getOauth2AccessTokenReqDTO().getGrantType());

        if (isUserAccessTokenType) {
            lifetimeInMillis = oAuthAppDO.getUserAccessTokenExpiryTime() * 1000;
            if (log.isDebugEnabled()) {
                log.debug("User Access Token Life time set to : " + lifetimeInMillis + "ms.");
            }
        } else {
            lifetimeInMillis = oAuthAppDO.getApplicationAccessTokenExpiryTime() * 1000;
            if (log.isDebugEnabled()) {
                log.debug("Application Access Token Life time set to : " + lifetimeInMillis + "ms.");
            }
        }

        if (lifetimeInMillis == 0) {
            if (isUserAccessTokenType) {
                lifetimeInMillis =
                        OAuthServerConfiguration.getInstance().getUserAccessTokenValidityPeriodInSeconds() * 1000;
                if (log.isDebugEnabled()) {
                    log.debug("User access token time was 0ms. Setting default user access token lifetime : "
                            + lifetimeInMillis + "ms.");
                }
            } else {
                lifetimeInMillis =
                        OAuthServerConfiguration.getInstance().getApplicationAccessTokenValidityPeriodInSeconds() * 1000;
                if (log.isDebugEnabled()) {
                    log.debug("Application access token time was 0ms. Setting default Application access token " +
                            "lifetime : " + lifetimeInMillis + "ms.");
                }
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("JWT Self Signed Access Token Life time set to : " + lifetimeInMillis + "ms.");
        }
        return lifetimeInMillis;
    }

    /**
     * Populate custom claims (For implicit grant)
     *
     * @param jwtClaimsSet
     * @param tokenReqMessageContext
     * @throws IdentityOAuth2Exception
     */
    protected void handleCustomClaims(JWTClaimsSet jwtClaimsSet,
                                      OAuthTokenReqMessageContext tokenReqMessageContext) throws IdentityOAuth2Exception {
        CustomClaimsCallbackHandler claimsCallBackHandler =
                OAuthServerConfiguration.getInstance().getOpenIDConnectCustomClaimsCallbackHandler();
        claimsCallBackHandler.handleCustomClaims(jwtClaimsSet, tokenReqMessageContext);
    }

    /**
     * Populate custom claims
     *
     * @param jwtClaimsSet
     * @param authzReqMessageContext
     * @throws IdentityOAuth2Exception
     */
    protected void handleCustomClaims(JWTClaimsSet jwtClaimsSet,
                                      OAuthAuthzReqMessageContext authzReqMessageContext) throws IdentityOAuth2Exception {
        CustomClaimsCallbackHandler claimsCallBackHandler =
                OAuthServerConfiguration.getInstance().getOpenIDConnectCustomClaimsCallbackHandler();
        claimsCallBackHandler.handleCustomClaims(jwtClaimsSet, authzReqMessageContext);
    }

    /**
     * To get the expiry time claim of the JWT token, based on the previous assertion expiry time.
     *
     * @param tokenReqMessageContext Token request message context.
     * @param jwtClaimsSet           JWT Claim set.
     * @return expiry time of the token.
     */
    private Date getExpiryTime(OAuthTokenReqMessageContext tokenReqMessageContext, JWTClaimsSet jwtClaimsSet) {

        Date originalExpiryTime = jwtClaimsSet.getExpirationTime();
        if (tokenReqMessageContext != null) {
            Object assertionExpiryTime = tokenReqMessageContext.getProperty(EXPIRY_TIME_JWT);
            if (assertionExpiryTime != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Expiry time from the previous token " + ((Date) assertionExpiryTime).getTime());
                }

                if (originalExpiryTime.after((Date) assertionExpiryTime)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Expiry time of newly generated token as per the configurations " + originalExpiryTime
                                + ", since this time is after assertion expiry time " + assertionExpiryTime
                                + " setting, " + assertionExpiryTime + " as the expiry time");
                    }
                    originalExpiryTime = (Date) assertionExpiryTime;
                }
            }
        }
        return originalExpiryTime;
    }



    private boolean isUserAccessTokenType(String grantType) throws IdentityOAuth2Exception {
        AuthorizationGrantHandler grantHandler =
                OAuthServerConfiguration.getInstance().getSupportedGrantTypes().get(grantType);
        // If grant handler is null ideally we would not come to this point as the flow will be broken before. So we
        // can guarantee grantHandler will not be null
        return grantHandler.isOfTypeApplicationUser();
    }

}
