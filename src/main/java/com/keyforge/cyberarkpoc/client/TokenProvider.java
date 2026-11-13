package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.config.CyberArkConfig;
import com.keyforge.cyberarkpoc.config.PolicyConfig;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

/**
 * Gets and caches a bearer token. The token is renewed {@link #REFRESH_MARGIN} before it expires. Two documented
 * requests ({@link Style}):
 * <ul>
 *   <li>{@link Style#PLATFORM_TOKEN}: {@code POST <identity>/oauth2/platformtoken}, URL-encoded form
 *       {@code grant_type=client_credentials}, {@code client_id}, {@code client_secret} (Use Case 1)</li>
 *   <li>{@link Style#CUSTOM_OAUTH2}: {@code POST <identity>/oauth2/token/<app_id>}, HTTP Basic auth with the service
 *       user, and either a JSON body {@code {"grant_type": "client_credentials"}} (SCA API reference, "Generate a
 *       public access token") or the form {@code grant_type=client_credentials[&scope=..]} ("Use queries" and the
 *       official SDK); the format and the optional scope are settings</li>
 * </ul>
 * A rejected request throws {@link CyberArkApiException} carrying CyberArk's response body; the body is never put in
 * the message unmasked.
 */
public final class TokenProvider {

    public enum Style { PLATFORM_TOKEN, CUSTOM_OAUTH2 }

    static final String ENDPOINT = "token";
    static final String POLICY_ENDPOINT = "policy-token";
    static final Duration REFRESH_MARGIN = Duration.ofSeconds(60);
    /** Used when the response has no {@code expires_in} (that field is ASSUMED). */
    static final Duration DEFAULT_LIFETIME = Duration.ofMinutes(5);

    private final Style style;
    private final String endpoint;
    private final URI tokenUrl;
    private final String clientId;
    private final String clientSecret;
    private final Duration timeout;
    private final String scope;
    private final CyberArkConfig.TokenBody body;
    private final HttpClient http;
    private final Clock clock;

    private String token;
    private Instant renewAt = Instant.MIN;
    /** Every token received, so error text can be masked (see {@link CyberArkClient#sanitize}). */
    private final java.util.Set<String> issued = new java.util.LinkedHashSet<>();

    /** The Identity token: the platform token, or an OAuth2 app token ({@link CyberArkConfig#authMethod()}). */
    public TokenProvider(CyberArkConfig config, HttpClient http, Clock clock) {
        this(config.authMethod() == CyberArkConfig.AuthMethod.OAUTH2_APP ? Style.CUSTOM_OAUTH2 : Style.PLATFORM_TOKEN,
                ENDPOINT, config.tokenUrl(), config.clientId(), config.clientSecret(), config.requestTimeout(),
                config.tokenScope(), config.tokenBody(), http, clock);
    }

    /** The custom OAuth2 token for the policy APIs. */
    public TokenProvider(PolicyConfig config, HttpClient http, Clock clock) {
        this(Style.CUSTOM_OAUTH2, POLICY_ENDPOINT, config.tokenUrl(), config.clientId(), config.clientSecret(),
                config.requestTimeout(), config.tokenScope(), config.tokenBody(), http, clock);
    }

    private TokenProvider(Style style, String endpoint, URI tokenUrl, String clientId, String clientSecret,
                          Duration timeout, String scope, CyberArkConfig.TokenBody body, HttpClient http,
                          Clock clock) {
        this.style = style;
        this.endpoint = endpoint;
        this.tokenUrl = tokenUrl;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.timeout = timeout;
        this.scope = scope;
        this.body = body;
        this.http = http;
        this.clock = clock;
    }

    public Style style() {
        return style;
    }

    public URI tokenUrl() {
        return tokenUrl;
    }

    /** How the token is requested, for display: never contains a credential. */
    public String requestDescription() {
        if (style == Style.PLATFORM_TOKEN) {
            return "POST " + tokenUrl + " (form: grant_type=client_credentials, client_id, client_secret)";
        }
        return "POST " + tokenUrl + " (Basic auth; " + (body == CyberArkConfig.TokenBody.FORM ? "form" : "JSON")
                + ": grant_type=client_credentials" + (scope == null ? "" : ", scope=" + scope) + ")";
    }

    /**
     * Requests a new token now (ignoring the cache) and returns CyberArk's token response body unmodified. The caller
     * must mask the token before showing the body ({@link #issuedTokens()}).
     */
    public synchronized String requestNow() {
        return requestToken();
    }

    public synchronized String token() {
        if (token == null || !clock.instant().isBefore(renewAt)) {
            requestToken();
        }
        return token;
    }

    /** Every token this provider has received. */
    public synchronized java.util.List<String> issuedTokens() {
        return java.util.List.copyOf(issued);
    }

    /** Forgets the cached token, e.g. after an API call answered 401. */
    public synchronized void invalidate() {
        token = null;
        renewAt = Instant.MIN;
    }

    /** Requests a token, caches it, and returns the raw response body. */
    private String requestToken() {
        HttpRequest.Builder builder = HttpRequest.newBuilder(tokenUrl)
                .timeout(timeout)
                .header("Accept", "application/json");
        if (style == Style.PLATFORM_TOKEN) {
            String form = "grant_type=client_credentials"
                    + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                    + "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);
            builder.header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form));
        } else {
            builder.header("Authorization", "Basic " + basicValue());
            if (body == CyberArkConfig.TokenBody.FORM) {
                String form = "grant_type=client_credentials"
                        + (scope == null ? "" : "&scope=" + URLEncoder.encode(scope, StandardCharsets.UTF_8));
                builder.header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form));
            } else {
                com.fasterxml.jackson.databind.node.ObjectNode json = Json.MAPPER.createObjectNode();
                json.put("grant_type", "client_credentials");
                if (scope != null) {
                    json.put("scope", scope);
                }
                builder.header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(json.toString()));
            }
        }
        HttpRequest request = builder.build();
        HttpResponse<String> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new CyberArkApiException(CyberArkApiException.Kind.TRANSPORT, endpoint, null,
                    "token request failed: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new CyberArkApiException(CyberArkApiException.Kind.TRANSPORT, endpoint, null, "interrupted", e);
        }
        int status = response.statusCode();
        String raw = response.body();
        if (status != 200) {
            // CyberArk's own answer (e.g. OAuth "error" / "error_description") explains the rejection. The message
            // gets a masked excerpt; the full body travels separately for callers that mask it themselves.
            boolean rejected = status == 400 || status == 401 || status == 403;
            String masked = ErrorSanitizer.clean(Json.snippet(raw), java.util.List.of(clientSecret, basicValue()));
            throw new CyberArkApiException(
                    rejected ? CyberArkApiException.Kind.AUTHENTICATION : CyberArkApiException.Kind.HTTP_STATUS,
                    endpoint, status, (rejected ? "token request was rejected" : "token endpoint failed")
                    + (masked.isEmpty() ? "" : ": " + masked), null, raw);
        }
        JsonNode parsed;
        try {
            parsed = Json.parse(endpoint, status, raw);
        } catch (CyberArkApiException e) {
            throw new CyberArkApiException(e.kind(), endpoint, status, "token response is not JSON", e, raw);
        }
        String accessToken = Json.text(parsed, "access_token");
        if (accessToken == null || accessToken.isBlank()) {
            throw new CyberArkApiException(CyberArkApiException.Kind.INVALID_RESPONSE, endpoint, status,
                    "token response has no 'access_token'", null, raw);
        }
        Duration lifetime = DEFAULT_LIFETIME;
        JsonNode expiresIn = parsed.get("expires_in");
        if (expiresIn != null && expiresIn.canConvertToLong() && expiresIn.asLong() > 0) {
            lifetime = Duration.ofSeconds(expiresIn.asLong());
        }
        Duration margin = lifetime.compareTo(REFRESH_MARGIN.multipliedBy(2)) > 0 ? REFRESH_MARGIN : Duration.ZERO;
        token = accessToken;
        issued.add(accessToken);
        renewAt = clock.instant().plus(lifetime).minus(margin);
        return raw;
    }

    /** The Basic-auth value sent by {@link Style#CUSTOM_OAUTH2}, so it can be masked like the secret. */
    public String basicValue() {
        return Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
    }
}
