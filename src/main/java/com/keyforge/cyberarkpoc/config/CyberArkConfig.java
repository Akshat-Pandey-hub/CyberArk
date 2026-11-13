package com.keyforge.cyberarkpoc.config;

import java.net.URI;
import java.time.Duration;
import java.util.Map;

/**
 * Connection settings for the CyberArk APIs.
 *
 * <p>The Identity base URL is configurable because the client mail puts the Identity calls on the {@code uap} host
 * while the official docs and SDK send them to the Identity host (see docs/API_CONTRACT.md). The token URL is
 * configurable on its own for the same reason; by default it is the Identity base URL plus
 * {@value #DEFAULT_TOKEN_PATH}. The policies (Use Case 2) have their own settings: {@link PolicyConfig}.
 *
 * <p>Two documented ways to get the Identity token ({@link AuthMethod}); which one the client's tenant accepts for
 * Redrock and the Roles API is not settled by the documentation (docs/API_CONTRACT.md), so it is a setting.
 *
 * @param authMethod     {@code platform}: {@code POST /oauth2/platformtoken} ("Create an API token");
 *                       {@code oauth2-app}: {@code POST /oauth2/token/<app id>} with Basic auth ("Use queries")
 * @param tokenScope     {@code scope} sent with {@code oauth2-app} (e.g. {@code reporting} per "Use queries"), or
 *                       {@code null} to send none
 * @param tokenBody      body format for {@code oauth2-app}: form (the "Use queries" client and the SDK) or JSON
 * @param redrockTimeout per-request timeout for {@code Redrock/query}; the docs say queries time out after two minutes
 */
public record CyberArkConfig(
        URI identityBaseUrl,
        URI tokenUrl,
        String clientId,
        String clientSecret,
        Duration requestTimeout,
        AuthMethod authMethod,
        String tokenScope,
        TokenBody tokenBody,
        Duration redrockTimeout) {

    public static final String ENV_IDENTITY_BASE_URL = "CYBERARK_IDENTITY_BASE_URL";
    public static final String ENV_TOKEN_URL = "CYBERARK_TOKEN_URL";
    public static final String ENV_CLIENT_ID = "CYBERARK_CLIENT_ID";
    public static final String ENV_CLIENT_SECRET = "CYBERARK_CLIENT_SECRET";
    public static final String ENV_TIMEOUT_SECONDS = "CYBERARK_TIMEOUT_SECONDS";
    public static final String ENV_IDENTITY_AUTH = "CYBERARK_IDENTITY_AUTH";
    public static final String ENV_IDENTITY_APP_ID = "CYBERARK_IDENTITY_APP_ID";
    public static final String ENV_IDENTITY_SCOPE = "CYBERARK_IDENTITY_SCOPE";
    public static final String ENV_IDENTITY_TOKEN_BODY = "CYBERARK_IDENTITY_TOKEN_BODY";
    public static final String ENV_REDROCK_TIMEOUT_SECONDS = "CYBERARK_REDROCK_TIMEOUT_SECONDS";

    public static final String DEFAULT_TOKEN_PATH = "/oauth2/platformtoken";
    public static final String APP_TOKEN_PATH = "/oauth2/token/";
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);
    /** The documented two-minute Redrock query timeout plus a margin, so CyberArk answers before we give up. */
    public static final Duration DEFAULT_REDROCK_TIMEOUT = Duration.ofSeconds(130);

    /** How the Identity token is requested. */
    public enum AuthMethod { PLATFORM, OAUTH2_APP }

    /** Body format of an {@code /oauth2/token/<app id>} request. */
    public enum TokenBody { FORM, JSON }

    /** The settings Use Case 1 has always used: platform token, default timeouts. */
    public CyberArkConfig(URI identityBaseUrl, URI tokenUrl, String clientId, String clientSecret,
                          Duration requestTimeout) {
        this(identityBaseUrl, tokenUrl, clientId, clientSecret, requestTimeout, AuthMethod.PLATFORM, null,
                TokenBody.FORM, null);
    }

    /**
     * Which documented role-members API to call (docs/API_CONTRACT.md §6): {@code roles} =
     * {@code POST /Roles/GetRoleMembers?name=} (Roles API reference, SDK; the default) or {@code saasmanage} =
     * {@code POST /SaasManage/GetRoleMembers?Name=} (data dictionary). Both response shapes are accepted either way;
     * switch once the client confirms which path their tenant answers.
     */
    public static final String ENV_ROLE_MEMBERS_API = "CYBERARK_ROLE_MEMBERS_API";

    public enum RoleMembersApi { ROLES, SAASMANAGE }

    /** Reads {@link #ENV_ROLE_MEMBERS_API}; absent means {@link RoleMembersApi#ROLES}. */
    public static RoleMembersApi roleMembersApi(Map<String, String> env) {
        String v = env.get(ENV_ROLE_MEMBERS_API);
        if (v == null || v.isBlank()) {
            return RoleMembersApi.ROLES;
        }
        return switch (v.trim().toLowerCase(java.util.Locale.ROOT)) {
            case "roles" -> RoleMembersApi.ROLES;
            case "saasmanage" -> RoleMembersApi.SAASMANAGE;
            default -> throw new ConfigException(ENV_ROLE_MEMBERS_API + " must be 'roles' or 'saasmanage' but was: " + v);
        };
    }

    public CyberArkConfig {
        identityBaseUrl = checkedBaseUrl(ENV_IDENTITY_BASE_URL, identityBaseUrl);
        authMethod = authMethod == null ? AuthMethod.PLATFORM : authMethod;
        if (tokenUrl == null && authMethod == AuthMethod.OAUTH2_APP) {
            throw new ConfigException(ENV_IDENTITY_AUTH + "=oauth2-app needs " + ENV_TOKEN_URL + " or "
                    + ENV_IDENTITY_APP_ID + " (the OAuth2 web app's Application ID)");
        }
        tokenUrl = tokenUrl == null
                ? URI.create(identityBaseUrl + DEFAULT_TOKEN_PATH)
                : checkedBaseUrl(ENV_TOKEN_URL, tokenUrl);
        tokenScope = tokenScope == null || tokenScope.isBlank() ? null : tokenScope.trim();
        tokenBody = tokenBody == null ? TokenBody.FORM : tokenBody;
        redrockTimeout = redrockTimeout == null ? DEFAULT_REDROCK_TIMEOUT : redrockTimeout;
        if (redrockTimeout.isZero() || redrockTimeout.isNegative()) {
            throw new ConfigException(ENV_REDROCK_TIMEOUT_SECONDS + " must be positive");
        }
        clientId = required(ENV_CLIENT_ID, clientId);
        clientSecret = required(ENV_CLIENT_SECRET, clientSecret);
        requestTimeout = requestTimeout == null ? DEFAULT_TIMEOUT : requestTimeout;
        if (requestTimeout.isZero() || requestTimeout.isNegative()) {
            throw new ConfigException(ENV_TIMEOUT_SECONDS + " must be positive");
        }
    }

    /** Builds the configuration from environment-style key/value pairs. */
    public static CyberArkConfig fromEnvironment(Map<String, String> env) {
        Duration requestTimeout = timeout(env);
        AuthMethod method = authMethod(env.get(ENV_IDENTITY_AUTH));
        URI identity = parseUri(ENV_IDENTITY_BASE_URL, env.get(ENV_IDENTITY_BASE_URL));
        String tokenUrl = env.get(ENV_TOKEN_URL);
        URI token = tokenUrl == null || tokenUrl.isBlank() ? null : parseUri(ENV_TOKEN_URL, tokenUrl);
        String appId = env.get(ENV_IDENTITY_APP_ID);
        if (token == null && method == AuthMethod.OAUTH2_APP && appId != null && !appId.isBlank()) {
            token = appTokenUrl(ENV_IDENTITY_APP_ID, identity.toString(), appId);
        }
        return new CyberArkConfig(identity, token, env.get(ENV_CLIENT_ID), env.get(ENV_CLIENT_SECRET),
                requestTimeout, method, env.get(ENV_IDENTITY_SCOPE),
                tokenBody(ENV_IDENTITY_TOKEN_BODY, env.get(ENV_IDENTITY_TOKEN_BODY), TokenBody.FORM),
                seconds(env, ENV_REDROCK_TIMEOUT_SECONDS, DEFAULT_REDROCK_TIMEOUT));
    }

    static AuthMethod authMethod(String value) {
        if (value == null || value.isBlank()) {
            return AuthMethod.PLATFORM;
        }
        return switch (value.trim().toLowerCase(java.util.Locale.ROOT)) {
            case "platform" -> AuthMethod.PLATFORM;
            case "oauth2-app" -> AuthMethod.OAUTH2_APP;
            default -> throw new ConfigException(ENV_IDENTITY_AUTH + " must be 'platform' or 'oauth2-app' but was: "
                    + value);
        };
    }

    static TokenBody tokenBody(String name, String value, TokenBody fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        return switch (value.trim().toLowerCase(java.util.Locale.ROOT)) {
            case "form" -> TokenBody.FORM;
            case "json" -> TokenBody.JSON;
            default -> throw new ConfigException(name + " must be 'form' or 'json' but was: " + value);
        };
    }

    /** {@code <identity base>/oauth2/token/<app id>}, after checking the app id is safe in a URL path. */
    static URI appTokenUrl(String appIdName, String identityBase, String appId) {
        if (!appId.trim().matches("[A-Za-z0-9._~-]+")) {
            throw new ConfigException(appIdName + " may only contain letters, digits and . _ ~ -");
        }
        String root = identityBase.trim();
        root = root.endsWith("/") ? root.substring(0, root.length() - 1) : root;
        return parseUri(appIdName, root + APP_TOKEN_PATH + appId.trim());
    }

    /** Never prints the secret. */
    @Override
    public String toString() {
        return "CyberArkConfig[identityBaseUrl=" + identityBaseUrl + ", authMethod=" + authMethod
                + ", tokenUrl=" + tokenUrl + ", clientId=" + clientId + ", clientSecret=***"
                + ", requestTimeout=" + requestTimeout + ", redrockTimeout=" + redrockTimeout + "]";
    }

    /** {@link #ENV_TIMEOUT_SECONDS}, or {@link #DEFAULT_TIMEOUT}; shared with {@link PolicyConfig}. */
    static Duration timeout(Map<String, String> env) {
        return seconds(env, ENV_TIMEOUT_SECONDS, DEFAULT_TIMEOUT);
    }

    private static Duration seconds(Map<String, String> env, String name, Duration fallback) {
        String value = env.get(name);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Duration.ofSeconds(Long.parseLong(value.trim()));
        } catch (NumberFormatException e) {
            throw new ConfigException(name + " must be a whole number of seconds");
        }
    }

    static URI parseUri(String name, String value) {
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
    static URI checkedBaseUrl(String name, URI uri) {
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

    static String required(String name, String value) {
        if (value == null || value.isBlank()) {
            throw new ConfigException(name + " is required");
        }
        return value;
    }
}
