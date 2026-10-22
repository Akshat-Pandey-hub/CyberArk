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
 * Read-only client for the CyberArk PVWA REST API (PAM Self-Hosted), following
 * docs/API_CONTRACT_PVWA.md (each endpoint taken from the official documentation page named there).
 *
 * <p>Only two POST calls exist: Logon and Logoff. Every other call is a GET whose path must match
 * {@link #READ_PATHS}; anything else (password retrieval, account actions such as Verify/Change/Reconcile)
 * is refused before a request is sent. Every response is passed through {@link SecretRedactor}.
 *
 * <p>One session per client: logon happens on the first call, the session is renewed after
 * {@link PvwaConfig#sessionRenewAfter()} (the documented default session is 20 minutes), and
 * {@link #close()} always logs off.
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

    private final PvwaConfig config;
    private final HttpClient http;
    private final Clock clock;

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
     * GET a documented read path with optional query parameters. The response is redacted. On HTTP 401
     * the session is renewed once and the call retried.
     */
    public JsonNode get(String path, Map<String, String> query) {
        if (!isAllowedReadPath(path)) {
            throw new IllegalArgumentException("not an allowed read-only PVWA path: " + path);
        }
        ensureSession();
        HttpResponse<String> response = send(path, getRequest(path, query));
        if (response.statusCode() == 401) {
            relogon();
            response = send(path, getRequest(path, query));
        }
        int status = response.statusCode();
        if (status == 401 || status == 403) {
            throw new CyberArkApiException(CyberArkApiException.Kind.AUTHENTICATION, path, status,
                    status == 401 ? "session token not accepted" : "the user lacks permission: "
                            + Json.snippet(response.body()));
        }
        if (status < 200 || status > 299) {
            throw new CyberArkApiException(CyberArkApiException.Kind.HTTP_STATUS, path, status,
                    Json.snippet(response.body()));
        }
        return SecretRedactor.redact(Json.parse(path, status, response.body())).value();
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
        HttpResponse<String> response = send("logon", request);
        int status = response.statusCode();
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

    private HttpResponse<String> send(String endpoint, HttpRequest request) {
        try {
            return http.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new CyberArkApiException(CyberArkApiException.Kind.TRANSPORT, endpoint, null,
                    e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage()), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new CyberArkApiException(CyberArkApiException.Kind.TRANSPORT, endpoint, null, "interrupted", e);
        }
    }
}
