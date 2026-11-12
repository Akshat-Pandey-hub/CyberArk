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
 *       user, JSON body {@code {"grant_type": "client_credentials"}} (SCA API reference, "Generate a public access
 *       token"; Use Case 2)</li>
 * </ul>
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
    private final HttpClient http;
    private final Clock clock;

    private String token;
    private Instant renewAt = Instant.MIN;
    /** Every token received, so error text can be masked (see {@link CyberArkClient#sanitize}). */
    private final java.util.Set<String> issued = new java.util.LinkedHashSet<>();

    /** The platform token for the Identity calls. */
    public TokenProvider(CyberArkConfig config, HttpClient http, Clock clock) {
        this(Style.PLATFORM_TOKEN, ENDPOINT, config.tokenUrl(), config.clientId(), config.clientSecret(),
                config.requestTimeout(), http, clock);
    }

    /** The custom OAuth2 token for the policy APIs. */
    public TokenProvider(PolicyConfig config, HttpClient http, Clock clock) {
        this(Style.CUSTOM_OAUTH2, POLICY_ENDPOINT, config.tokenUrl(), config.clientId(), config.clientSecret(),
                config.requestTimeout(), http, clock);
    }

    private TokenProvider(Style style, String endpoint, URI tokenUrl, String clientId, String clientSecret,
                          Duration timeout, HttpClient http, Clock clock) {
        this.style = style;
        this.endpoint = endpoint;
        this.tokenUrl = tokenUrl;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.timeout = timeout;
        this.http = http;
        this.clock = clock;
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

    private void requestToken() {
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
            String basic = Base64.getEncoder().encodeToString(
                    (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
            builder.header("Authorization", "Basic " + basic)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"grant_type\":\"client_credentials\"}"));
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
        if (status != 200) {
            // The response body may echo request details, so it is not included.
            boolean rejected = status == 400 || status == 401 || status == 403;
            throw new CyberArkApiException(
                    rejected ? CyberArkApiException.Kind.AUTHENTICATION : CyberArkApiException.Kind.HTTP_STATUS,
                    endpoint, status, rejected ? "token request was rejected" : "token endpoint failed");
        }
        JsonNode body = Json.parse(endpoint, status, response.body());
        String accessToken = Json.text(body, "access_token");
        if (accessToken == null || accessToken.isBlank()) {
            throw new CyberArkApiException(CyberArkApiException.Kind.INVALID_RESPONSE, endpoint, status,
                    "token response has no 'access_token'");
        }
        Duration lifetime = DEFAULT_LIFETIME;
        JsonNode expiresIn = body.get("expires_in");
        if (expiresIn != null && expiresIn.canConvertToLong() && expiresIn.asLong() > 0) {
            lifetime = Duration.ofSeconds(expiresIn.asLong());
        }
        Duration margin = lifetime.compareTo(REFRESH_MARGIN.multipliedBy(2)) > 0 ? REFRESH_MARGIN : Duration.ZERO;
        token = accessToken;
        issued.add(accessToken);
        renewAt = clock.instant().plus(lifetime).minus(margin);
    }
}
