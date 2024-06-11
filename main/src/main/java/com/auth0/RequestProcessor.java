package com.auth0;

import static com.auth0.InvalidRequestException.API_ERROR;
import static com.auth0.InvalidRequestException.INVALID_STATE_ERROR;
import static com.auth0.InvalidRequestException.JWT_VERIFICATION_ERROR;
import static com.auth0.InvalidRequestException.MISSING_ACCESS_TOKEN;
import static com.auth0.InvalidRequestException.MISSING_ID_TOKEN;

import com.auth0.client.auth.AuthAPI;
import com.auth0.exception.Auth0Exception;
import com.auth0.json.auth.TokenHolder;
import com.auth0.net.Response;
import java.util.Arrays;
import java.util.List;
import org.apache.commons.lang3.Validate;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Main class to handle the Authorize Redirect request.
 * It will try to parse the parameters looking for tokens or an authorization code to perform a Code Exchange against the Auth0 servers.
 */
class RequestProcessor {

    private static final String KEY_STATE = "state";
    private static final String KEY_ERROR = "error";
    private static final String KEY_ERROR_DESCRIPTION = "error_description";
    private static final String KEY_EXPIRES_IN = "expires_in";
    private static final String KEY_ACCESS_TOKEN = "access_token";
    private static final String KEY_ID_TOKEN = "id_token";
    private static final String KEY_TOKEN_TYPE = "token_type";
    private static final String KEY_CODE = "code";
    private static final String KEY_TOKEN = "token";
    private static final String KEY_RESPONSE_MODE = "response_mode";
    private static final String KEY_FORM_POST = "form_post";
    private static final String KEY_MAX_AGE = "max_age";

    // Visible for testing
    final IdTokenVerifier.Options verifyOptions;
    final boolean useLegacySameSiteCookie;

    private final String responseType;
    private final AuthAPI client;
    private final IdTokenVerifier tokenVerifier;
    private final String organization;
    private final String invitation;
    private final String cookiePath;


    static class Builder {
        private final AuthAPI client;
        private final String responseType;
        private final IdTokenVerifier.Options verifyOptions;
        private boolean useLegacySameSiteCookie = true;
        private IdTokenVerifier tokenVerifier;
        private String organization;
        private String invitation;
        private String cookiePath;

        Builder(AuthAPI client, String responseType, IdTokenVerifier.Options verifyOptions) {
            Validate.notNull(client);
            Validate.notNull(responseType);
            Validate.notNull(verifyOptions);
            this.client = client;
            this.responseType = responseType;
            this.verifyOptions = verifyOptions;
        }

        Builder withCookiePath(String cookiePath) {
            this.cookiePath = cookiePath;
            return this;
        }

        Builder withLegacySameSiteCookie(boolean useLegacySameSiteCookie) {
            this.useLegacySameSiteCookie = useLegacySameSiteCookie;
            return this;
        }

        Builder withIdTokenVerifier(IdTokenVerifier verifier) {
            this.tokenVerifier = verifier;
            return this;
        }

        Builder withOrganization(String organization) {
            this.organization = organization;
            return this;
        }

        Builder withInvitation(String invitation) {
            this.invitation = invitation;
            return this;
        }

        RequestProcessor build() {
            return new RequestProcessor(client, responseType, verifyOptions,
                    this.tokenVerifier == null ? new IdTokenVerifier() : this.tokenVerifier,
                    useLegacySameSiteCookie, organization, invitation, cookiePath);
        }
    }

    private RequestProcessor(AuthAPI client, String responseType, IdTokenVerifier.Options verifyOptions, IdTokenVerifier tokenVerifier, boolean useLegacySameSiteCookie, String organization, String invitation, String cookiePath) {
        Validate.notNull(client);
        Validate.notNull(responseType);
        Validate.notNull(verifyOptions);
        this.client = client;
        this.responseType = responseType;
        this.verifyOptions = verifyOptions;
        this.tokenVerifier = tokenVerifier;
        this.useLegacySameSiteCookie = useLegacySameSiteCookie;
        this.organization = organization;
        this.invitation = invitation;
        this.cookiePath = cookiePath;
    }

    /**
     * Getter for the AuthAPI client instance.
     * Used to customize options such as Telemetry and Logging.
     *
     * @return the AuthAPI client.
     */
    AuthAPI getClient() {
        return client;
    }

    /**
     * Pre builds an Auth0 Authorize Url with the given redirect URI, state and nonce parameters.
     *
     * @param serverWebExchange     the serverWebExchange, used to store state and nonce in the Session
     * @param redirectUri the url to call with the authentication result.
     * @param state       a valid state value.
     * @param nonce       the nonce value that will be used if the response type contains 'id_token'. Can be null.
     * @return the authorize url builder to continue any further parameter customization.
     */
    AuthorizeUrl buildAuthorizeUrl(ServerWebExchange serverWebExchange, String redirectUri,
                                   String state, String nonce) {

        AuthorizeUrl creator = new AuthorizeUrl(client, serverWebExchange, redirectUri, responseType)
                .withState(state);

        if (this.organization != null) {
            creator.withOrganization(organization);
        }
        if (this.invitation != null) {
            creator.withInvitation(invitation);
        }
        if (this.cookiePath != null) {
            creator.withCookiePath(this.cookiePath);
        }

        // null response means state and nonce will be stored in session, so legacy cookie flag does not apply
        if (serverWebExchange.getResponse() != null) {
            creator.withLegacySameSiteCookie(useLegacySameSiteCookie);
        }


        return getAuthorizeUrl(nonce, creator);
    }

    /**
     * Entrypoint for HTTP request
     * <p>
     * 1). Responsible for validating the request.
     * 2). Exchanging the authorization code received with this HTTP request for Auth0 tokens.
     * 3). Validating the ID Token.
     * 4). Clearing the stored state, nonce and max_age values.
     * 5). Handling success and any failure outcomes.
     *
     */
    Mono<Tokens> process(ServerWebExchange serverWebExchange) {

        ServerHttpRequest request = serverWebExchange.getRequest();
        ServerHttpResponse response = serverWebExchange.getResponse();

        return assertNoError(request)
            .then(assertValidState(serverWebExchange))
            .then(getTokens(serverWebExchange, request, response));
    }

    private Mono<Tokens> getTokens(ServerWebExchange serverWebExchange,
        ServerHttpRequest request, ServerHttpResponse response) {
        Tokens frontChannelTokens = getFrontChannelTokens(request);
        List<String> responseTypeList = getResponseType();

        if (responseTypeList.contains(KEY_ID_TOKEN) && frontChannelTokens.getIdToken() == null) {
            return Mono.error(new InvalidRequestException(MISSING_ID_TOKEN, "ID Token is missing from the response."));
        }
        if (responseTypeList.contains(KEY_TOKEN) && frontChannelTokens.getAccessToken() == null) {
            return Mono.error(new InvalidRequestException(MISSING_ACCESS_TOKEN, "Access Token is missing from the response."));
        }

        String nonce;
        if (response != null) {
            // Nonce dynamically set and changes on every request.
            nonce = TransientCookieStore.getNonce(request, response);

            // Just in case the developer created the authorizeUrl that stores state/nonce in the session
            if (nonce == null) {
                return RandomStorage.removeSessionNonce(serverWebExchange)
                    .flatMap(newNonce -> {
                        verifyOptions.setNonce(newNonce);
                        return getVerifiedTokens(serverWebExchange, frontChannelTokens,
                            responseTypeList);
                    });
            } else {
                verifyOptions.setNonce(nonce);
                return getVerifiedTokens(serverWebExchange, frontChannelTokens, responseTypeList);
            }
        } else {
            return RandomStorage.removeSessionNonce(serverWebExchange)
                .flatMap(newNonce -> {
                    verifyOptions.setNonce(newNonce);
                    return getVerifiedTokens(serverWebExchange, frontChannelTokens,
                        responseTypeList);
                });
        }
    }

    static boolean requiresFormPostResponseMode(List<String> responseType) {
        return responseType != null &&
                (responseType.contains(KEY_TOKEN) || responseType.contains(KEY_ID_TOKEN));
    }

    /**
     * Obtains code request tokens (if using Code flow) and validates the ID token.
     * @param exchange the ServerWebExchange
     * @param frontChannelTokens the tokens obtained from the front channel
     * @param responseTypeList the reponse types
     * @return a Tokens object that wraps the values obtained from the front-channel and/or the code request response.
     */
    private Mono<Tokens> getVerifiedTokens(ServerWebExchange exchange, Tokens frontChannelTokens, List<String> responseTypeList) {
        ServerHttpRequest request = exchange.getRequest();

        String authorizationCode = request.getQueryParams().getFirst(KEY_CODE);
        Tokens codeExchangeTokens = null;

        try {
            if (responseTypeList.contains(KEY_ID_TOKEN)) {
                // Implicit/Hybrid flow: must verify front-channel ID Token first
                tokenVerifier.verify(frontChannelTokens.getIdToken(), verifyOptions);
            }
            if (responseTypeList.contains(KEY_CODE)) {
                // Code/Hybrid flow
                String redirectUri = request.getURI().toString();
                codeExchangeTokens = exchangeCodeForTokens(authorizationCode, redirectUri);
                if (!responseTypeList.contains(KEY_ID_TOKEN)) {
                    // If we already verified the front-channel token, don't verify it again.
                    String idTokenFromCodeExchange = codeExchangeTokens.getIdToken();
                    if (idTokenFromCodeExchange != null) {
                        tokenVerifier.verify(idTokenFromCodeExchange, verifyOptions);
                    }
                }
            }
        } catch (TokenValidationException e) {
            return Mono.error(new IdentityVerificationException(JWT_VERIFICATION_ERROR, "An error occurred while trying to verify the ID Token.", e));
        } catch (Auth0Exception e) {
            return Mono.error(new IdentityVerificationException(API_ERROR, "An error occurred while exchanging the authorization code.", e));
        }
        // Keep the front-channel ID Token and the code-exchange Access Token.
        return mergeTokens(frontChannelTokens, codeExchangeTokens);
    }

    List<String> getResponseType() {
        return Arrays.asList(responseType.split(" "));
    }

    private AuthorizeUrl getAuthorizeUrl(String nonce, AuthorizeUrl creator) {
        List<String> responseTypeList = getResponseType();
        if (responseTypeList.contains(KEY_ID_TOKEN) && nonce != null) {
            creator.withNonce(nonce);
        }
        if (requiresFormPostResponseMode(responseTypeList)) {
            creator.withParameter(KEY_RESPONSE_MODE, KEY_FORM_POST);
        }
        if (verifyOptions.getMaxAge() != null) {
            creator.withParameter(KEY_MAX_AGE, verifyOptions.getMaxAge().toString());
        }
        return creator;
    }

    /**
     * Extract the tokens from the request parameters, present when using the Implicit or Hybrid Grant.
     *
     * @param request the request
     * @return a new instance of Tokens wrapping the values present in the request parameters.
     */
    private Tokens getFrontChannelTokens(ServerHttpRequest request) {
        Long expiresIn = request.getQueryParams().getFirst(KEY_EXPIRES_IN) == null ? null : Long.parseLong(request.getQueryParams().getFirst(KEY_EXPIRES_IN));
        return new Tokens(request.getQueryParams().getFirst(KEY_ACCESS_TOKEN), request.getQueryParams().getFirst(KEY_ID_TOKEN), null, request.getQueryParams().getFirst(KEY_TOKEN_TYPE), expiresIn);
    }

    /**
     * Checks for the presence of an error in the request parameters
     *
     * @param request the request
     * @throws InvalidRequestException if the request contains an error
     */
    private Mono<Void> assertNoError(ServerHttpRequest request) {
        String error = request.getQueryParams().getFirst(KEY_ERROR);
        if (error != null) {
            String errorDescription = request.getQueryParams().getFirst(KEY_ERROR_DESCRIPTION);
            return Mono.error(new InvalidRequestException(error, errorDescription));
        }
        return Mono.empty();
    }

    /**
     * Checks whether the state received in the request parameters is the same as the one in the state cookie or session
     * for this request.
     *
     * @param serverWebExchange the serverWebExchange
     * @throws InvalidRequestException if the request contains a different state from the expected one
     */
    private Mono<Void> assertValidState(ServerWebExchange serverWebExchange) {
        ServerHttpRequest request = serverWebExchange.getRequest();
        ServerHttpResponse response = serverWebExchange.getResponse();
        String stateFromRequest = request.getQueryParams().getFirst(KEY_STATE);

        if (stateFromRequest == null) {
            return Mono.error(new InvalidRequestException(INVALID_STATE_ERROR, "The received state doesn't match the expected one. No state parameter was found on the authorization response."));
        }

        // If response is null, check the Session.
        // This can happen when the deprecated handle method that only takes the request parameter is called
        if (response == null) {
            return checkSessionState(serverWebExchange, stateFromRequest);
        }

        String cookieState = TransientCookieStore.getState(request, response);

        // Just in case state was stored in Session by building auth URL with deprecated method, but then called the
        // supported handle method with the request and response
        if (cookieState == null) {
            return SessionUtils.get(serverWebExchange, StorageUtils.STATE_KEY)
                .flatMap(state -> {
                    if (state == null) {
                        return Mono.error(new InvalidRequestException(INVALID_STATE_ERROR, "The received state doesn't match the expected one. No state cookie or state session attribute found. Check that you are using non-deprecated methods and that cookies are not being removed on the server."));
                    }
                    return checkSessionState(serverWebExchange, stateFromRequest);
                });
        }

        if (!cookieState.equals(stateFromRequest)) {
            return Mono.error(new InvalidRequestException(INVALID_STATE_ERROR, "The received state doesn't match the expected one."));
        }

        return Mono.empty();
    }

    private Mono<Void> checkSessionState(ServerWebExchange serverWebExchange, String stateFromRequest) {
        return RandomStorage.checkSessionState(serverWebExchange, stateFromRequest)
            .flatMap(valid -> {
                if (!valid) {
                    return Mono.error(new InvalidRequestException(INVALID_STATE_ERROR, "The received state doesn't match the expected one."));
                }
                return Mono.empty();
            });
    }

    /**
     * Calls the Auth0 Authentication API to perform a Code Exchange.
     *
     * @param authorizationCode the code received on the login response.
     * @param redirectUri       the redirect uri used on login request.
     * @return a new instance of {@link Tokens} with the received credentials.
     * @throws Auth0Exception if the request to the Auth0 server failed.
     * @see AuthAPI#exchangeCode(String, String)
     */
    private Tokens exchangeCodeForTokens(String authorizationCode, String redirectUri) throws Auth0Exception {
        Response<TokenHolder> tokenHolderResponse = client
                .exchangeCode(authorizationCode, redirectUri)
                .execute();
        TokenHolder holder = tokenHolderResponse.getBody();
        return new Tokens(holder.getAccessToken(), holder.getIdToken(), holder.getRefreshToken(), holder.getTokenType(), holder.getExpiresIn());
    }

    /**
     * Used to keep the best version of each token.
     * It will prioritize the ID Token received in the front-channel, and the Access Token received in the code exchange request.
     *
     * @param frontChannelTokens the front-channel obtained tokens.
     * @param codeExchangeTokens the code-exchange obtained tokens.
     * @return a merged version of Tokens using the best tokens when possible.
     */
    private Mono<Tokens> mergeTokens(Tokens frontChannelTokens, Tokens codeExchangeTokens) {
        if (codeExchangeTokens == null) {
            return Mono.just(frontChannelTokens);
        }

        // Prefer access token from the code exchange
        String accessToken;
        String type;
        Long expiresIn;

        if (codeExchangeTokens.getAccessToken() != null) {
            accessToken = codeExchangeTokens.getAccessToken();
            type = codeExchangeTokens.getType();
            expiresIn = codeExchangeTokens.getExpiresIn();
        } else {
            accessToken = frontChannelTokens.getAccessToken();
            type = frontChannelTokens.getType();
            expiresIn = frontChannelTokens.getExpiresIn();
        }

        // Prefer ID token from the front-channel
        String idToken = frontChannelTokens.getIdToken() != null ? frontChannelTokens.getIdToken() : codeExchangeTokens.getIdToken();

        // Refresh token only available from the code exchange
        String refreshToken = codeExchangeTokens.getRefreshToken();

        return Mono.just(new Tokens(accessToken, idToken, refreshToken, type, expiresIn));
    }

}