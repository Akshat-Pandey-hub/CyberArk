package com.keyforge.cyberarkpoc.config;

import java.net.URI;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;

/**
 * Settings for the CyberArk PVWA (PAM Self-Hosted) REST API, as requested in the KeyForge PVWA read-only
 * access document.
 *
 * <p>{@code baseUrl} is the PVWA application URL ending in {@code /PasswordVault}, e.g.
 * {@code https://pvwa.example.com/PasswordVault}. Logon uses
 * {@code POST {baseUrl}/API/auth/{authMethod}/Logon/} with a username and password (official "Logon" page).
 */
public record PvwaConfig(
        URI baseUrl,
        String authMethod,
        String username,
        String password,
        Duration requestTimeout,
        Duration sessionRenewAfter) {

    public static final String ENV_BASE_URL = "CYBERARK_PVWA_BASE_URL";
    public static final String ENV_AUTH_METHOD = "CYBERARK_PVWA_AUTH_METHOD";
    public static final String ENV_USERNAME = "CYBERARK_PVWA_USERNAME";
    public static final String ENV_PASSWORD = "CYBERARK_PVWA_PASSWORD";
    public static final String ENV_TIMEOUT_SECONDS = "CYBERARK_TIMEOUT_SECONDS";

    /** Logon methods on the official Logon page (2nd gen API). */
    public static final Map<String, String> AUTH_METHODS = Map.of(
            "cyberark", "Cyberark", "ldap", "LDAP", "radius", "RADIUS", "windows", "Windows");

    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);
    /**
     * The documented default session length is 20 minutes; the session is renewed (logoff + logon) after
     * 18 minutes so a long run never uses an expired token.
     */
    public static final Duration DEFAULT_RENEW_AFTER = Duration.ofMinutes(18);

    public PvwaConfig {
        if (baseUrl == null || baseUrl.getScheme() == null || baseUrl.getHost() == null) {
            throw new ConfigException(ENV_BASE_URL + " must be an absolute URL such as https://<pvwa-fqdn>/PasswordVault");
        }
        String host = baseUrl.getHost();
        boolean loopback = host.equals("localhost") || host.equals("127.0.0.1") || host.equals("[::1]");
        if (!baseUrl.getScheme().equals("https") && !(baseUrl.getScheme().equals("http") && loopback)) {
            throw new ConfigException(ENV_BASE_URL + " must use https (plain http is allowed only for localhost): "
                    + baseUrl);
        }
        String text = baseUrl.toString();
        while (text.endsWith("/")) {
            text = text.substring(0, text.length() - 1);
        }
        baseUrl = URI.create(text);
        String method = authMethod == null || authMethod.isBlank() ? "cyberark" : authMethod.trim().toLowerCase(Locale.ROOT);
        if (!AUTH_METHODS.containsKey(method)) {
            throw new ConfigException(ENV_AUTH_METHOD + " must be one of CyberArk, LDAP, RADIUS, Windows but was: "
                    + authMethod);
        }
        authMethod = AUTH_METHODS.get(method);
        if (username == null || username.isBlank()) {
            throw new ConfigException(ENV_USERNAME + " is required");
        }
        if (password == null || password.isEmpty()) {
            throw new ConfigException(ENV_PASSWORD + " is required");
        }
        requestTimeout = requestTimeout == null ? DEFAULT_TIMEOUT : requestTimeout;
        sessionRenewAfter = sessionRenewAfter == null ? DEFAULT_RENEW_AFTER : sessionRenewAfter;
        if (requestTimeout.isZero() || requestTimeout.isNegative()) {
            throw new ConfigException(ENV_TIMEOUT_SECONDS + " must be positive");
        }
    }

    public static PvwaConfig fromEnvironment(Map<String, String> env) {
        String base = env.get(ENV_BASE_URL);
        if (base == null || base.isBlank()) {
            throw new ConfigException(ENV_BASE_URL + " is required");
        }
        URI uri;
        try {
            uri = URI.create(base.trim());
        } catch (IllegalArgumentException e) {
            throw new ConfigException(ENV_BASE_URL + " is not a valid URL: " + base);
        }
        Duration timeout = DEFAULT_TIMEOUT;
        String t = env.get(ENV_TIMEOUT_SECONDS);
        if (t != null && !t.isBlank()) {
            try {
                timeout = Duration.ofSeconds(Long.parseLong(t.trim()));
            } catch (NumberFormatException e) {
                throw new ConfigException(ENV_TIMEOUT_SECONDS + " must be a whole number of seconds");
            }
        }
        return new PvwaConfig(uri, env.get(ENV_AUTH_METHOD), env.get(ENV_USERNAME), env.get(ENV_PASSWORD),
                timeout, DEFAULT_RENEW_AFTER);
    }

    /** Never prints the password. */
    @Override
    public String toString() {
        return "PvwaConfig[baseUrl=" + baseUrl + ", authMethod=" + authMethod + ", username=" + username
                + ", password=***, requestTimeout=" + requestTimeout + "]";
    }
}
