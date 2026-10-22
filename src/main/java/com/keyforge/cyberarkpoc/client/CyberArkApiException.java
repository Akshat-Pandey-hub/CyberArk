package com.keyforge.cyberarkpoc.client;

/** A CyberArk call that did not produce a usable answer. The secret and token are never included. */
public class CyberArkApiException extends RuntimeException {

    public enum Kind {
        /** Token request rejected, or an API call answered 401/403. */
        AUTHENTICATION,
        /** Any other non-2xx HTTP status. */
        HTTP_STATUS,
        /** HTTP 200 but the Identity envelope said {@code "success": false}. */
        API_FAILURE,
        /** The body was not JSON or lacked a field the contract requires. */
        INVALID_RESPONSE,
        /** Connection refused, timeout, or interrupted. */
        TRANSPORT,
        /** Policy paging returned the same {@code nextToken} twice. */
        PAGINATION
    }

    private final Kind kind;
    private final String endpoint;
    private final Integer httpStatus;

    public CyberArkApiException(Kind kind, String endpoint, Integer httpStatus, String message, Throwable cause) {
        super("[" + kind + "] " + endpoint + (httpStatus == null ? "" : " (HTTP " + httpStatus + ")") + ": " + message,
                cause);
        this.kind = kind;
        this.endpoint = endpoint;
        this.httpStatus = httpStatus;
    }

    public CyberArkApiException(Kind kind, String endpoint, Integer httpStatus, String message) {
        this(kind, endpoint, httpStatus, message, null);
    }

    public Kind kind() {
        return kind;
    }

    public String endpoint() {
        return endpoint;
    }

    public Integer httpStatus() {
        return httpStatus;
    }
}
