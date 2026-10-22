package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.config.CyberArkConfig;

import java.io.IOException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Gets and caches the platform token ({@code POST <tokenUrl>}, form {@code grant_type=client_credentials},
 * {@code client_id}, {@code client_secret}). The token is renewed {@link #REFRESH_MARGIN} before it expires.
 */
public final class TokenProvider {

    static final String ENDPOINT = "token";
    static final Duration REFRESH_MARGIN = Duration.ofSeconds(60);
    /** Used when the response has no {@code expires_in} (that field is ASSUMED). */
    static final Duration DEFAULT_LIFETIME = Duration.ofMinutes(5);

    private final CyberArkConfig config;
    private final HttpClient http;
    private final Clock clock;

    private String token;
    private Instant renewAt = Instant.MIN;

    public TokenProvider(CyberArkConfig config, HttpClient http, Clock clock) {
        this.config = config;
        this.http = http;
        this.clock = clock;
    }

    public synchronized String token() {
        if (token == null || !clock.instant().isBefore(renewAt)) {
            requestToken();
        }
        return token;
    }

    /** Forgets the cached token, e.g. after an API call answered 401. */
    public synchronized void invalidate() {
        token = null;
        renewAt = Instant.MIN;
    }

    private void requestToken() {
        String form = "grant_type=client_credentials"
                + "&client_id=" + URLEncoder.encode(config.clientId(), StandardCharsets.UTF_8)
                + "&client_secret=" + URLEncoder.encode(config.clientSecret(), StandardCharsets.UTF_8);
        HttpRequest request = HttpRequest.newBuilder(config.tokenUrl())
                .timeout(config.requestTimeout())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();
        HttpResponse<String> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new CyberArkApiException(CyberArkApiException.Kind.TRANSPORT, ENDPOINT, null,
                    "token request failed: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new CyberArkApiException(CyberArkApiException.Kind.TRANSPORT, ENDPOINT, null, "interrupted", e);
        }
        int status = response.statusCode();
        if (status != 200) {
            // The response body may echo request details, so it is not included.
            boolean rejected = status == 400 || status == 401 || status == 403;
            throw new CyberArkApiException(
                    rejected ? CyberArkApiException.Kind.AUTHENTICATION : CyberArkApiException.Kind.HTTP_STATUS,
                    ENDPOINT, status, rejected ? "token request was rejected" : "token endpoint failed");
        }
        JsonNode body = Json.parse(ENDPOINT, status, response.body());
        String accessToken = Json.text(body, "access_token");
        if (accessToken == null || accessToken.isBlank()) {
            throw new CyberArkApiException(CyberArkApiException.Kind.INVALID_RESPONSE, ENDPOINT, status,
                    "token response has no 'access_token'");
        }
        Duration lifetime = DEFAULT_LIFETIME;
        JsonNode expiresIn = body.get("expires_in");
        if (expiresIn != null && expiresIn.canConvertToLong() && expiresIn.asLong() > 0) {
            lifetime = Duration.ofSeconds(expiresIn.asLong());
        }
        Duration margin = lifetime.compareTo(REFRESH_MARGIN.multipliedBy(2)) > 0 ? REFRESH_MARGIN : Duration.ZERO;
        token = accessToken;
        renewAt = clock.instant().plus(lifetime).minus(margin);
    }
}
