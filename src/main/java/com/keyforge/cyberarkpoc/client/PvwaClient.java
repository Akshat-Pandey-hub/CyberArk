package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.config.PvwaConfig;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.Map;
import java.util.StringJoiner;
import java.util.regex.Pattern;

/**
 * Read-only client for the CyberArk PVWA REST API (PAM Self-Hosted). Each endpoint is taken from its official
 * CyberArk documentation page.
 *
 * <p>Only two POST calls exist: Logon and Logoff. Every other call is a GET whose path must match
 * {@link #READ_PATHS}; anything else (password retrieval, account actions such as Verify/Change/Reconcile)
 * is refused before a request is sent. Every response is passed through {@link SecretRedactor}.
 *
 * <p>One session per client: logon happens on the first call, the session is renewed after
 * {@link PvwaConfig#sessionRenewAfter()} (the documented default session is 20 minutes), and
 * {@link #close()} always logs off.
 *
 * <p>Every response must arrive in full within {@link PvwaConfig#requestTimeout()} (status, headers and body). A read
 * that gets HTTP 429, 502, 503 or 504, or fails on the network, is retried up to {@link PvwaConfig#maxRetries()}
 * times, waiting as the server's {@code Retry-After} says (at most {@link #MAX_RETRY_WAIT}) or 1 s, 2 s, 4 s, ...
 * Only reads are retried; Logon and Logoff are not.
 */
public final class PvwaClient implements AutoCloseable {

    static final String LOGON_PATH = "/API/auth/%s/Logon/";
    static final String LOGOFF_PATH = "/API/Auth/Logoff/";
    public static final String VERIFY_PATH = "/WebServices/PIMServices.svc/Verify/";

    /** The documented read endpoints of the request document (see the contract). Nothing else can be called. */
    static final List<Pattern> READ_PATHS = List.of(
            Pattern.compile("/WebServices/PIMServices\\.svc/Verify/"),
            Pattern.compile("/API/Safes/"),
            Pattern.compile("/API/Safes/[^/]+/Members/"),
            Pattern.compile("/API/Accounts"),
            Pattern.compile("/API/Accounts/"),
            Pattern.compile("/API/platforms/targets/"),
            Pattern.compile("/API/Platforms/[^/]+/"),
            Pattern.compile("/API/Users/"),
            Pattern.compile("/API/UserGroups/"),
            Pattern.compile("/API/DiscoveredAccounts/"),
            Pattern.compile("/WebServices/PIMServices\\.svc/Accounts/[^/]+/Activities/"));

    /** The statuses a read is retried on: rate limiting and a temporarily unavailable server or gateway. */
    static final Set<Integer> RETRY_STATUSES = Set.of(429, 502, 503, 504);
    /** The longest wait before a retry, even if the server's Retry-After asks for more. */
    static final java.time.Duration MAX_RETRY_WAIT = java.time.Duration.ofSeconds(60);

    private final PvwaConfig config;
    private final HttpClient http;
    private final Clock clock;
    private java.time.Duration retryBaseDelay = java.time.Duration.ofSeconds(1);
    private int retries;

    private String sessionToken;
    private Instant loggedOnAt;
    private int logons;
    private String logoffProblem;
    /** Every session token this client received, so {@link #sanitize} can mask them in any text. */
    private final Set<String> seenTokens = new LinkedHashSet<>();

    public PvwaClient(PvwaConfig config) {
        this(config, HttpClient.newBuilder()
                .connectTimeout(config.requestTimeout())
                .followRedirects(HttpClient.Redirect.NEVER)
                .build(), Clock.systemUTC());
    }

    public PvwaClient(PvwaConfig config, HttpClient http, Clock clock) {
        this.config = config;
        this.http = http;
        this.clock = clock;
    }

    /** The server's identity from the documented Verify call (health check). */
    public JsonNode verify() {
        return get(VERIFY_PATH, Map.of());
    }

    /**
     * GET a documented read path with optional query parameters. The response is redacted. On HTTP 401 the session
     * is renewed once and the call retried; HTTP 429 / 502 / 503 / 504 and network failures are retried as described
     * in the class comment.
     */
    public JsonNode get(String path, Map<String, String> query) {
        if (!isAllowedReadPath(path)) {
            throw new IllegalArgumentException("not an allowed read-only PVWA path: " + path);
        }
        ensureSession();
        boolean renewed = false;
        int attempt = 0;
        Received response;
        while (true) {
            try {
                response = send(path, getRequest(path, query));
            } catch (CyberArkApiException e) {
                if (e.kind() == CyberArkApiException.Kind.TRANSPORT && attempt < config.maxRetries()) {
                    attempt++;
                    waitBeforeRetry(path, attempt, null);
                    continue;
                }
                throw e;
            }
            if (response.status() == 401 && !renewed) {
                renewed = true;
                relogon();
                continue;
            }
            if (RETRY_STATUSES.contains(response.status()) && attempt < config.maxRetries()) {
                attempt++;
                waitBeforeRetry(path, attempt, response.headers().firstValue("Retry-After").orElse(null));
                continue;
            }
            break;
        }
        int status = response.status();
        if (status == 401 || status == 403) {
            throw new CyberArkApiException(CyberArkApiException.Kind.AUTHENTICATION, path, status,
                    status == 401 ? "session token not accepted" : "the user lacks permission: "
                            + Json.snippet(response.body()));
        }
        if (status < 200 || status > 299) {
            String retried = attempt == 0 ? "" : " (after " + attempt + " retr" + (attempt == 1 ? "y" : "ies") + ")";
            throw new CyberArkApiException(CyberArkApiException.Kind.HTTP_STATUS, path, status,
                    (status == 429 ? "rate limited by PVWA (HTTP 429)" + retried + ": " : retried.isEmpty() ? ""
                            : "HTTP " + status + retried + ": ") + Json.snippet(response.body()));
        }
        return SecretRedactor.redact(Json.parse(path, status, response.body())).value();
    }

    /** How many reads were retried in this client's life (rate limits, unavailable server, network failures). */
    public int retryCount() {
        return retries;
    }

    /** Test hook: the first retry wait when the server sends no Retry-After (doubles each time). */
    PvwaClient retryBaseDelay(java.time.Duration delay) {
        this.retryBaseDelay = delay;
        return this;
    }

    private void waitBeforeRetry(String path, int attempt, String retryAfter) {
        retries++;
        long millis = retryBaseDelay.toMillis() << Math.min(attempt - 1, 10);
        if (retryAfter != null) {
            try {
                millis = Math.max(0, Long.parseLong(retryAfter.trim())) * 1000;
            } catch (NumberFormatException ignored) {
                // an HTTP-date Retry-After: use the backoff instead
            }
        }
        millis = Math.min(millis, MAX_RETRY_WAIT.toMillis());
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new CyberArkApiException(CyberArkApiException.Kind.TRANSPORT, path, null, "interrupted", e);
        }
    }

    static boolean isAllowedReadPath(String path) {
        return path != null && READ_PATHS.stream().anyMatch(p -> p.matcher(path).matches());
    }

    /**
     * Masks this client's vault password and every session token it received, then applies
     * {@link ErrorSanitizer}. Use it on any text that leaves the service (REST, run log, console).
     */
    public String sanitize(String text) {
        List<String> sensitive = new ArrayList<>(seenTokens);
        sensitive.add(config.password());
        return ErrorSanitizer.clean(text, sensitive);
    }

    /** How many logons this client has made (1 normally; more after renewals). */
    public int logonCount() {
        return logons;
    }

    /** {@code null} if the last logoff succeeded (or none was needed), else what went wrong. */
    public String logoffProblem() {
        return logoffProblem;
    }

    /** Logs off if a session is open. A failed logoff is recorded, not thrown, so it never hides a result. */
    @Override
    public void close() {
        logoff();
    }

    // ---- session ---------------------------------------------------------------------------

    private void ensureSession() {
        if (sessionToken == null) {
            logon();
        } else if (!clock.instant().isBefore(loggedOnAt.plus(config.sessionRenewAfter()))) {
            relogon();
        }
    }

    private void relogon() {
        logoff();
        logon();
    }

    private void logon() {
        String path = String.format(LOGON_PATH, config.authMethod());
        String body;
        try {
            Map<String, String> credentials = new LinkedHashMap<>();
            credentials.put("username", config.username());
            credentials.put("password", config.password());
            body = Json.MAPPER.writeValueAsString(credentials);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
        HttpRequest request = HttpRequest.newBuilder(URI.create(config.baseUrl() + path))
                .timeout(config.requestTimeout())
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        Received response = send("logon", request);
        int status = response.status();
        if (status < 200 || status > 299) {
            // The request held the password, so only the server's own message is reported.
            throw new CyberArkApiException(
                    status == 401 || status == 403 || status == 400
                            ? CyberArkApiException.Kind.AUTHENTICATION : CyberArkApiException.Kind.HTTP_STATUS,
                    "logon", status, "logon was rejected: " + Json.snippet(response.body()));
        }
        JsonNode token = Json.parse("logon", status, response.body());
        if (!token.isTextual() || token.asText().isBlank()) {
            throw new CyberArkApiException(CyberArkApiException.Kind.INVALID_RESPONSE, "logon", status,
                    "logon did not return a session token string");
        }
        sessionToken = token.asText();
        seenTokens.add(sessionToken);
        loggedOnAt = clock.instant();
        logons++;
    }

    private void logoff() {
        if (sessionToken == null) {
            return;
        }
        HttpRequest request = HttpRequest.newBuilder(URI.create(config.baseUrl() + LOGOFF_PATH))
                .timeout(config.requestTimeout())
                .header("Authorization", sessionToken)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        sessionToken = null;
        try {
            int status = http.send(request, HttpResponse.BodyHandlers.ofString()).statusCode();
            logoffProblem = status >= 200 && status <= 299 ? null : "logoff returned HTTP " + status;
        } catch (IOException e) {
            logoffProblem = "logoff failed: " + e.getMessage();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logoffProblem = "logoff interrupted";
        }
    }

    // ---- requests --------------------------------------------------------------------------

    private HttpRequest getRequest(String path, Map<String, String> query) {
        StringJoiner q = new StringJoiner("&");
        query.forEach((k, v) -> q.add(URLEncoder.encode(k, StandardCharsets.UTF_8) + "="
                + URLEncoder.encode(v, StandardCharsets.UTF_8).replace("+", "%20")));
        String url = config.baseUrl() + path + (q.length() == 0 ? "" : "?" + q);
        return HttpRequest.newBuilder(URI.create(url))
                .timeout(config.requestTimeout())
                .header("Authorization", sessionToken)
                .header("Accept", "application/json")
                .GET()
                .build();
    }

    private record Received(int status, java.net.http.HttpHeaders headers, String body) {
    }

    /**
     * One request whose whole response (status, headers and body) must arrive within the request timeout: Java's
     * request timeout covers only the status and headers, so a {@link Deadline} stops a body still arriving after it.
     */
    private Received send(String endpoint, HttpRequest request) {
        long deadline = System.nanoTime() + config.requestTimeout().toNanos();
        HttpResponse<java.io.InputStream> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
        } catch (IOException e) {
            throw new CyberArkApiException(CyberArkApiException.Kind.TRANSPORT, endpoint, null,
                    e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage()), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new CyberArkApiException(CyberArkApiException.Kind.TRANSPORT, endpoint, null, "interrupted", e);
        }
        java.io.ByteArrayOutputStream received = new java.io.ByteArrayOutputStream();
        Deadline watch = new Deadline(Thread.currentThread(), response.body(), Math.max(1, deadline - System.nanoTime()));
        try (java.io.InputStream in = response.body()) {
            in.transferTo(received);
            if (watch.stop()) { // the deadline fired just as the last byte arrived: treat as late
                throw new IOException("deadline");
            }
        } catch (IOException e) {
            boolean late = watch.stop();
            throw new CyberArkApiException(CyberArkApiException.Kind.TRANSPORT, endpoint, response.statusCode(), late
                    ? "HttpTimeoutException: the whole response did not arrive within "
                            + config.requestTimeout().toSeconds() + " s (" + received.size() + " bytes received)"
                    : "the connection ended before the whole response arrived (" + received.size()
                            + " bytes received): " + e.getClass().getSimpleName(), e);
        } finally {
            watch.stop();
        }
        return new Received(response.statusCode(), response.headers(), received.toString(StandardCharsets.UTF_8));
    }
}
