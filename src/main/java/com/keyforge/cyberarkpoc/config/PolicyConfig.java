package com.keyforge.cyberarkpoc.config;

import java.net.URI;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;

/**
 * Settings for Use Case 2 (policy health), separate from the Identity settings of Use Case 1.
 *
 * <p>Two official APIs list the policies (docs/API_CONTRACT.md, Use Case 2):
 * <ul>
 *   <li>{@link Api#UAP}: Access Control Policies, {@code GET https://<subdomain>.uap.cyberark.cloud/api/policies}</li>
 *   <li>{@link Api#SCA}: the SCA Policies API, {@code GET https://<subdomain>.sca.cyberark.cloud/api/policies}. The
 *       Access Control Policies reference says tenants that show their policies on SCA's Policies page must use it.</li>
 * </ul>
 * Both are called with the custom OAuth2 token ({@code POST https://<tenant>.id.cyberark.cloud/oauth2/token/<app_id>}),
 * never with the platform token: the official "Create an API token" page says SCA APIs and cloud-console policies
 * need it.
 *
 * @param baseUrl      the policy API base URL, ending in {@code /api}
 * @param tokenUrl     the custom OAuth2 token endpoint
 * @param clientId     the service user (OAuth confidential client) login name, sent as HTTP Basic user
 * @param clientSecret its password
 * @param pageSize     {@code limit} per page (UAP only; documented maximum 50)
 * @param maxPages     safety stop for the UAP paging
 * @param tokenScope   {@code scope} sent in the token request, or {@code null} to send none (the SCA reference sends
 *                     none; the app's scope is configured on the app)
 * @param tokenBody    token request body: JSON as in the SCA API reference (the default), or form
 */
public record PolicyConfig(
        Api api,
        URI baseUrl,
        URI tokenUrl,
        String clientId,
        String clientSecret,
        int pageSize,
        int maxPages,
        Duration requestTimeout,
        String tokenScope,
        CyberArkConfig.TokenBody tokenBody) {

    public enum Api { UAP, SCA }

    public static final String ENV_POLICY_API = "CYBERARK_POLICY_API";
    public static final String ENV_UAP_BASE_URL = "CYBERARK_UAP_BASE_URL";
    public static final String ENV_SCA_BASE_URL = "CYBERARK_SCA_BASE_URL";
    public static final String ENV_POLICY_APP_ID = "CYBERARK_POLICY_APP_ID";
    public static final String ENV_POLICY_TOKEN_URL = "CYBERARK_POLICY_TOKEN_URL";
    public static final String ENV_POLICY_CLIENT_ID = "CYBERARK_POLICY_CLIENT_ID";
    public static final String ENV_POLICY_CLIENT_SECRET = "CYBERARK_POLICY_CLIENT_SECRET";
    public static final String ENV_POLICY_PAGE_SIZE = "CYBERARK_POLICY_PAGE_SIZE";
    public static final String ENV_POLICY_SCOPE = "CYBERARK_POLICY_SCOPE";
    public static final String ENV_POLICY_TOKEN_BODY = "CYBERARK_POLICY_TOKEN_BODY";

    /** Documented: {@code limit} "You can request up to 50 policies", default 10. */
    public static final int MAX_PAGE_SIZE = 50;
    public static final int DEFAULT_MAX_PAGES = 10_000;
    public static final String TOKEN_PATH = "/oauth2/token/";

    /** JSON token body without a scope, as in the SCA API reference. */
    public PolicyConfig(Api api, URI baseUrl, URI tokenUrl, String clientId, String clientSecret, int pageSize,
                        int maxPages, Duration requestTimeout) {
        this(api, baseUrl, tokenUrl, clientId, clientSecret, pageSize, maxPages, requestTimeout, null,
                CyberArkConfig.TokenBody.JSON);
    }

    public PolicyConfig {
        if (api == null) {
            throw new ConfigException(ENV_POLICY_API + " is required");
        }
        baseUrl = CyberArkConfig.checkedBaseUrl(baseUrlVariable(api), baseUrl);
        tokenUrl = CyberArkConfig.checkedBaseUrl(ENV_POLICY_TOKEN_URL, tokenUrl);
        clientId = CyberArkConfig.required(ENV_POLICY_CLIENT_ID, clientId);
        clientSecret = CyberArkConfig.required(ENV_POLICY_CLIENT_SECRET, clientSecret);
        if (pageSize < 1 || pageSize > MAX_PAGE_SIZE) {
            throw new ConfigException(ENV_POLICY_PAGE_SIZE + " must be between 1 and " + MAX_PAGE_SIZE);
        }
        if (maxPages < 1) {
            throw new ConfigException("maxPages must be at least 1");
        }
        requestTimeout = requestTimeout == null ? CyberArkConfig.DEFAULT_TIMEOUT : requestTimeout;
        tokenScope = tokenScope == null || tokenScope.isBlank() ? null : tokenScope.trim();
        tokenBody = tokenBody == null ? CyberArkConfig.TokenBody.JSON : tokenBody;
    }

    /**
     * Reads the settings. The token URL is {@value #ENV_POLICY_TOKEN_URL}, or else
     * {@code CYBERARK_IDENTITY_BASE_URL + /oauth2/token/ + CYBERARK_POLICY_APP_ID}. The credentials fall back to
     * {@code CYBERARK_CLIENT_ID} / {@code CYBERARK_CLIENT_SECRET} when the policy-specific ones are not set, since the
     * custom OAuth2 app may use the same service user.
     */
    public static PolicyConfig fromEnvironment(Map<String, String> env) {
        Api api = api(env.get(ENV_POLICY_API));
        String baseVar = baseUrlVariable(api);
        URI tokenUrl;
        String explicitToken = env.get(ENV_POLICY_TOKEN_URL);
        if (explicitToken != null && !explicitToken.isBlank()) {
            tokenUrl = CyberArkConfig.parseUri(ENV_POLICY_TOKEN_URL, explicitToken);
        } else {
            String identity = env.get(CyberArkConfig.ENV_IDENTITY_BASE_URL);
            String appId = env.get(ENV_POLICY_APP_ID);
            if (identity == null || identity.isBlank() || appId == null || appId.isBlank()) {
                throw new ConfigException("set " + ENV_POLICY_TOKEN_URL + ", or " + CyberArkConfig.ENV_IDENTITY_BASE_URL
                        + " and " + ENV_POLICY_APP_ID + " (the custom OAuth2 server's Application ID)");
            }
            tokenUrl = CyberArkConfig.appTokenUrl(ENV_POLICY_APP_ID, identity, appId);
        }
        return new PolicyConfig(
                api,
                CyberArkConfig.parseUri(baseVar, env.get(baseVar)),
                tokenUrl,
                firstSet(env, ENV_POLICY_CLIENT_ID, CyberArkConfig.ENV_CLIENT_ID),
                firstSet(env, ENV_POLICY_CLIENT_SECRET, CyberArkConfig.ENV_CLIENT_SECRET),
                pageSize(env.get(ENV_POLICY_PAGE_SIZE)),
                DEFAULT_MAX_PAGES,
                CyberArkConfig.timeout(env),
                env.get(ENV_POLICY_SCOPE),
                CyberArkConfig.tokenBody(ENV_POLICY_TOKEN_BODY, env.get(ENV_POLICY_TOKEN_BODY),
                        CyberArkConfig.TokenBody.JSON));
    }

    public static String baseUrlVariable(Api api) {
        return api == Api.SCA ? ENV_SCA_BASE_URL : ENV_UAP_BASE_URL;
    }

    /** Never prints the secret. */
    @Override
    public String toString() {
        return "PolicyConfig[api=" + api + ", baseUrl=" + baseUrl + ", tokenUrl=" + tokenUrl + ", clientId=" + clientId
                + ", clientSecret=***, pageSize=" + pageSize + ", requestTimeout=" + requestTimeout + ", tokenBody=" + tokenBody
                + "]";
    }

    private static Api api(String value) {
        if (value == null || value.isBlank()) {
            return Api.UAP;
        }
        return switch (value.trim().toLowerCase(Locale.ROOT)) {
            case "uap" -> Api.UAP;
            case "sca" -> Api.SCA;
            default -> throw new ConfigException(ENV_POLICY_API + " must be 'uap' or 'sca' but was: " + value);
        };
    }

    private static int pageSize(String value) {
        if (value == null || value.isBlank()) {
            return MAX_PAGE_SIZE;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            throw new ConfigException(ENV_POLICY_PAGE_SIZE + " must be an integer but was: " + value);
        }
    }

    private static String firstSet(Map<String, String> env, String preferred, String fallback) {
        String v = env.get(preferred);
        return v == null || v.isBlank() ? env.get(fallback) : v;
    }
}
