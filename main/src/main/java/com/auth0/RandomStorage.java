package com.auth0;


import jakarta.servlet.http.HttpSession;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

class RandomStorage extends SessionUtils {

    /**
     * Check's if the request {@link HttpSession} saved state is equal to the given state.
     * After the check, the value will be removed from the session.
     *
     * @param exchange   the serverWebExchange
     * @param state the state value to compare against.
     * @return whether the state matches the expected one or not.
     */
    static Mono<Boolean> checkSessionState(ServerWebExchange exchange, String state) {
        return remove(exchange, StorageUtils.STATE_KEY)
            .map(currentState -> ((currentState == null && state == null) || currentState != null && currentState.equals(state)));
    }

    /**
     * Saves the given state in the request {@link HttpSession}.
     * If a state is already bound to the session, the value is replaced.
     *
     * @param exchange   the serverWebExchange.
     * @param state the state value to set.
     */
    static Mono<WebSession> setSessionState(ServerWebExchange exchange, String state) {
        return set(exchange, StorageUtils.STATE_KEY, state);
    }

    /**
     * Saves the given nonce in the request {@link HttpSession}.
     * If a nonce is already bound to the session, the value is replaced.
     *
     * @param exchange   the serverWebExchange.
     * @param nonce the nonce value to set.
     */
    static Mono<WebSession> setSessionNonce(ServerWebExchange exchange, String nonce) {
        return set(exchange, StorageUtils.NONCE_KEY, nonce);
    }

    /**
     * Removes the nonce present in the request {@link HttpSession} and then returns it.
     *
     * @param exchange   the serverWebExchange.
     * @return the nonce value or null if it was not set.
     */
    static Mono<String> removeSessionNonce(ServerWebExchange exchange) {
        return remove(exchange, StorageUtils.NONCE_KEY)
            .map(nonce -> nonce != null ? nonce.toString() : null);
    }
}