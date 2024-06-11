package com.auth0;

import org.apache.commons.lang3.Validate;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

/**
 * Helper class to handle easy session key-value storage.
 */
@SuppressWarnings({"WeakerAccess", "unused"})
public abstract class SessionUtils {

    /**
     * Extracts the HttpSession from the given request.
     *
     * @param serverWebExchange a valid request to get the session from
     * @return the session of the request
     */
    protected static Mono<WebSession> getSession(ServerWebExchange serverWebExchange) {
        return serverWebExchange.getSession();
    }

    /**
     * Set's the attribute value to the request session.
     *
     * @param serverWebExchange   a valid request to get the session from
     * @param name  the name of the attribute
     * @param value the value to set
     */
    public static Mono<WebSession> set(ServerWebExchange serverWebExchange, String name, Object value) {
        Validate.notNull(serverWebExchange);
        Validate.notNull(name);
        return serverWebExchange.getSession().map(session -> {
            session.getAttributes().put(name, value);
            return session;
        });
    }

    /**
     * Get the attribute with the given name from the request session.
     *
     * @param serverWebExchange  a valid request to get the session from
     * @param name the name of the attribute
     * @return the attribute stored in the session or null if it doesn't exists
     */
    public static Mono<Object> get(ServerWebExchange serverWebExchange, String name) {
        Validate.notNull(serverWebExchange);
        Validate.notNull(name);

        return serverWebExchange.getSession()
            .map(session -> session.getAttributes().get(name));
    }

    /**
     * Same as {@link #get(ServerWebExchange, String)} but it also removes the value from the request session.
     *
     * @param serverWebExchange  a valid request to get the session from
     * @param name the name of the attribute
     * @return the attribute stored in the session or null if it doesn't exists
     */
    public static Mono<Object> remove(ServerWebExchange serverWebExchange, String name) {
        Validate.notNull(serverWebExchange);
        Validate.notNull(name);
        Object value = get(serverWebExchange, name);
        return serverWebExchange.getSession()
            .map(session -> session.getAttributes().remove(name));
    }
}
