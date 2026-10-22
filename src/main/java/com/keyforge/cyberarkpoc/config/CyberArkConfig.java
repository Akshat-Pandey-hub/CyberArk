package com.keyforge.cyberarkpoc.config;

import java.net.URI;
import java.time.Duration;
import java.util.Map;

/**
 * Connection settings for the CyberArk APIs.
 *
 * <p>Identity calls (token, Redrock, Roles) and Access Control Policies calls go to two separately
 * configurable base URLs, because the client mail puts the Identity calls on the {@code uap} host
 * while the official SDK sends them to the Identity host (see docs/API_CONTRACT.md). The token URL
 * is configurable on its own for the same reason; by default it is the Identity base URL plus
 * {@value #DEFAULT_TOKEN_PATH}.
 */
public record CyberArkConfig(
        URI identityBaseUrl,
        URI uapBaseUrl,
        URI tokenUrl,
        String clientId,
        String clientSecret,
        Duration requestTimeout) {

    public static final String ENV_IDENTITY_BASE_URL = "CYBERARK_IDENTITY_BASE_URL";
    public static final String ENV_UAP_BASE_URL = "CYBERARK_UAP_BASE_URL";
    public static final String ENV_TOKEN_URL = "CYBERARK_TOKEN_URL";
    public static final String ENV_CLIENT_ID = "CYBERARK_CLIENT_ID";
    public static final String ENV_CLIENT_SECRET = "CYBERARK_CLIENT_SECRET";
    public static final String ENV_TIMEOUT_SECONDS = "CYBERARK_TIMEOUT_SECONDS";

    public static final String DEFAULT_TOKEN_PATH = "/oauth2/platformtoken";
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    public CyberArkConfig {
        identityBaseUrl = checkedBaseUrl(ENV_IDENTITY_BASE_URL, identityBaseUrl);
        uapBaseUrl = checkedBaseUrl(ENV_UAP_BASE_URL, uapBaseUrl);
        tokenUrl = tokenUrl == null
                ? URI.create(identityBaseUrl + DEFAULT_TOKEN_PATH)
                : checkedBaseUrl(ENV_TOKEN_URL, tokenUrl);
        clientId = required(ENV_CLIENT_ID, clientId);
        clientSecret = required(ENV_CLIENT_SECRET, clientSecret);
        requestTimeout = requestTimeout == null ? DEFAULT_TIMEOUT : requestTimeout;
        if (requestTimeout.isZero() || requestTimeout.isNegative()) {
            throw new ConfigException(ENV_TIMEOUT_SECONDS + " must be positive");
        }
    }

    /** Builds the configuration from environment-style key/value pairs. */
    public static CyberArkConfig fromEnvironment(Map<String, String> env) {
        String timeout = env.get(ENV_TIMEOUT_SECONDS);
        Duration requestTimeout = DEFAULT_TIMEOUT;
        if (timeout != null && !timeout.isBlank()) {
            try {
                requestTimeout = Duration.ofSeconds(Long.parseLong(timeout.trim()));
            } catch (NumberFormatException e) {
                throw new ConfigException(ENV_TIMEOUT_SECONDS + " must be a whole number of seconds");
            }
        }
        String tokenUrl = env.get(ENV_TOKEN_URL);
        return new CyberArkConfig(
                parseUri(ENV_IDENTITY_BASE_URL, env.get(ENV_IDENTITY_BASE_URL)),
                parseUri(ENV_UAP_BASE_URL, env.get(ENV_UAP_BASE_URL)),
                tokenUrl == null || tokenUrl.isBlank() ? null : parseUri(ENV_TOKEN_URL, tokenUrl),
                env.get(ENV_CLIENT_ID),
                env.get(ENV_CLIENT_SECRET),
                requestTimeout);
    }

    /** Never prints the secret. */
    @Override
    public String toString() {
        return "CyberArkConfig[identityBaseUrl=" + identityBaseUrl + ", uapBaseUrl=" + uapBaseUrl
                + ", tokenUrl=" + tokenUrl + ", clientId=" + clientId + ", clientSecret=***"
                + ", requestTimeout=" + requestTimeout + "]";
    }

    private static URI parseUri(String name, String value) {
        if (value == null || value.isBlank()) {
            throw new ConfigException(name + " is required");
        }
        try {
            return URI.create(value.trim());
        } catch (IllegalArgumentException e) {
            throw new ConfigException(name + " is not a valid URL: " + value);
        }
    }

    /** https only, except plain http to a loopback host (the local mock). Trailing slash removed. */
    private static URI checkedBaseUrl(String name, URI uri) {
        if (uri == null) {
            throw new ConfigException(name + " is required");
        }
        String scheme = uri.getScheme();
        String host = uri.getHost();
        if (scheme == null || host == null) {
            throw new ConfigException(name + " must be an absolute URL: " + uri);
        }
        boolean loopback = host.equals("localhost") || host.equals("127.0.0.1") || host.equals("[::1]");
        if (!scheme.equals("https") && !(scheme.equals("http") && loopback)) {
            throw new ConfigException(name + " must use https (plain http is allowed only for localhost): " + uri);
        }
        String text = uri.toString();
        return text.endsWith("/") ? URI.create(text.substring(0, text.length() - 1)) : uri;
    }

    private static String required(String name, String value) {
        if (value == null || value.isBlank()) {
            throw new ConfigException(name + " is required");
        }
        return value;
    }
}
