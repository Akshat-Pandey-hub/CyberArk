package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.keyforge.cyberarkpoc.config.CyberArkConfig;
import com.keyforge.cyberarkpoc.config.PolicyConfig;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * The four cloud operations as plain pass-through calls: one request to CyberArk, built as documented, and CyberArk's
 * answer returned as received. No paging loops, no parsing into our own objects, no storage.
 *
 * <ul>
 *   <li>{@link #token}: request a token with the configured login and report whether it worked</li>
 *   <li>{@link #redrock}: {@code POST <identity>/Redrock/query} with the caller's query, one page</li>
 *   <li>{@link #role}: {@code POST <identity>/Roles/GetRole?Name=<role UUID>}</li>
 *   <li>{@link #policies}: {@code GET <uap>/policies?limit=&nextToken=&filter=&q=&sort=}, one page</li>
 * </ul>
 *
 * <p>Every call returns an envelope: what was sent (never a credential), {@code http_status}, {@code ok}, and
 * CyberArk's body under {@code response} (its bytes unchanged, see {@link ResponseBody}) or, when it is not JSON, under
 * {@code response_text} exactly as received, plus {@code completeness} (whether the whole body arrived, how many
 * records it holds, and whether more pages exist). Large bodies are kept in a temporary file, not in memory; callers
 * must {@link ResponseBody#release} the envelope after writing it. The only change ever made to CyberArk's body is replacing
 * this service's own credentials and tokens with {@code ***} if they appear in it; {@code masked} says when that
 * happened. A 401 renews the token and retries once; any other status is returned as it is, never as an empty
 * success.
 */
public final class CloudApi {

    public enum Target { IDENTITY, POLICIES }

    static final String MASK = "***";

    /** Keeps numbers exactly as written (no double rounding) and rejects duplicate keys instead of dropping one. */
    static final ObjectMapper EXACT = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
            .nodeFactory(JsonNodeFactory.withExactBigDecimals(true))
            .build();

    private final CyberArkConfig identity;
    private final PolicyConfig policy;
    private final HttpClient http;
    private TokenProvider identityTokens;
    private TokenProvider policyTokens;
    private ResponseBody.Settings spool = ResponseBody.Settings.defaults();

    /** Either config may be {@code null} when only the other target's operations are used. */
    public CloudApi(CyberArkConfig identity, PolicyConfig policy) {
        this(identity, policy, HttpClient.newBuilder()
                .connectTimeout(identity != null ? identity.requestTimeout() : policy.requestTimeout())
                .followRedirects(HttpClient.Redirect.NEVER)
                .build());
    }

    public CloudApi(CyberArkConfig identity, PolicyConfig policy, HttpClient http) {
        this.identity = identity;
        this.policy = policy;
        this.http = http;
    }

    /** Where large response bodies are kept while they are checked and returned ({@link ResponseBody}). */
    public CloudApi withSpool(ResponseBody.Settings settings) {
        this.spool = settings;
        return this;
    }

    // ---- the four operations ----------------------------------------------------------------

    /** Requests a fresh token for the target and reports the outcome; the token itself is never returned. */
    public Map<String, Object> token(Target target) {
        TokenProvider tokens = tokens(target);
        Map<String, Object> out = start("token");
        out.put("target", target.name().toLowerCase(java.util.Locale.ROOT));
        out.put("auth", tokens.requestDescription());
        long started = System.nanoTime();
        String raw;
        try {
            raw = tokens.requestNow();
        } catch (CyberArkApiException e) {
            return tokenFailure(out, e, started);
        }
        out.put("http_status", 200);
        putTokenBody(out, raw);
        if (out.get("response") instanceof ObjectNode node) {
            for (String field : List.of("access_token", "refresh_token", "id_token")) {
                if (node.has(field)) {
                    node.put(field, MASK);
                    out.put("masked", true);
                }
            }
        }
        return finish(out, true, null, null, started);
    }

    /**
     * The approver-role query of the client mail (kept as an optional default for callers that pass no script):
     * {@code SELECT ID, Name, RoleType, ReadOnly, Description FROM Role WHERE Name LIKE '<pattern>' ORDER BY ID}.
     */
    public static String approverRoleScript(String rolePattern) {
        if (rolePattern == null || rolePattern.isBlank()) {
            throw new IllegalArgumentException("a role name pattern is required");
        }
        return "SELECT " + CyberArkClient.ROLE_COLUMNS + " FROM Role WHERE Name LIKE '"
                + CyberArkClient.sqlLiteral(rolePattern.trim()) + "' ORDER BY ID";
    }

    /**
     * Runs the caller's Redrock query exactly as given: the script (columns, table, filters, sorting) is sent
     * unchanged, and CyberArk filters, sorts and pages on its side. Only one request is made; nothing is fetched in
     * full and then filtered or paged here. The documented {@code args} {@code PageNumber}, {@code PageSize},
     * {@code Limit} and {@code Caching} are each sent only when given (nothing is derived from another); with none
     * given, no {@code args} object is sent.
     */
    public Map<String, Object> redrock(String script, Integer pageNumber, Integer pageSize, Integer limit,
                                       Integer caching) {
        requireIdentity();
        if (script == null || script.isBlank()) {
            throw new IllegalArgumentException("a Redrock query (script) is required");
        }
        if (pageNumber != null && pageNumber < 0) {
            throw new IllegalArgumentException("pageNumber must not be negative");
        }
        if (pageSize != null && pageSize < 1) {
            throw new IllegalArgumentException("pageSize must be at least 1");
        }
        if (limit != null && limit < 1) {
            throw new IllegalArgumentException("limit must be at least 1");
        }
        ObjectNode body = Json.MAPPER.createObjectNode();
        body.put("Script", script);
        ObjectNode args = Json.MAPPER.createObjectNode(); // "args": the official example's casing
        if (pageNumber != null) {
            args.put("PageNumber", pageNumber);
        }
        if (pageSize != null) {
            args.put("PageSize", pageSize);
        }
        if (limit != null) {
            args.put("Limit", limit);
        }
        if (caching != null) {
            args.put("Caching", caching);
        }
        if (!args.isEmpty()) {
            body.set("args", args);
        }
        URI uri = URI.create(identity.identityBaseUrl() + CyberArkClient.REDROCK_PATH);
        Map<String, Object> out = start("redrock");
        out.put("request", request("POST", uri, body));
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()));
        Shape shape = new Shape("redrock", true, Set.of(REDROCK_ROWS),
                Set.of(SUCCESS, MESSAGE, REDROCK_COUNT, REDROCK_FULL_COUNT));
        shape.params.put("pageNumber", pageNumber);
        shape.params.put("pageSize", pageSize);
        shape.params.put("limit", limit);
        return call(out, tokens(Target.IDENTITY), builder, identity.redrockTimeout(), shape);
    }

    /** GetRole. The role UUID goes in the {@code Name} query parameter (Roles API OpenAPI file). */
    public Map<String, Object> role(String roleId) {
        return role(roleId, null, null);
    }

    /**
     * GetRole with the documented optional query parameters {@code SuppressPrincipalsList} ("may make this call much
     * faster" by leaving the principals out) and {@code getRights}; each is sent only when given.
     */
    public Map<String, Object> role(String roleId, Boolean suppressPrincipalsList, Boolean getRights) {
        requireIdentity();
        if (roleId == null || roleId.isBlank()) {
            throw new IllegalArgumentException("id (the role UUID) is required");
        }
        StringBuilder query = new StringBuilder("Name=").append(encode(roleId.trim()));
        if (suppressPrincipalsList != null) {
            query.append("&SuppressPrincipalsList=").append(suppressPrincipalsList);
        }
        if (getRights != null) {
            query.append("&getRights=").append(getRights);
        }
        URI uri = URI.create(identity.identityBaseUrl() + CyberArkClient.GET_ROLE_PATH + "?" + query);
        Map<String, Object> out = start("role");
        out.put("request", request("POST", uri, null));
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).POST(HttpRequest.BodyPublishers.noBody());
        Shape shape = new Shape("role", true, Set.of(PRINCIPALS), Set.of(SUCCESS, MESSAGE));
        shape.params.put("SuppressPrincipalsList", suppressPrincipalsList);
        return call(out, tokens(Target.IDENTITY), builder, identity.requestTimeout(), shape);
    }

    /** One page of UAP policies, or the SCA list; see the full overload. */
    public Map<String, Object> policies(Integer limit, String nextToken, String filter, String q, String sort) {
        return policies(limit, nextToken, filter, q, sort, null, null, null, null);
    }

    /**
     * One page of policies. UAP: the documented {@code limit} (1-50), {@code nextToken}, {@code filter}, {@code q} and
     * {@code sort} are each sent only when given, URL-encoded and otherwise unchanged; CyberArk filters, sorts and pages
     * on its side, and nothing is filtered here. SCA (when configured): its own documented {@code cloud_provider},
     * {@code free_text}, {@code status} and {@code debug}, sent the same way. Parameters of the other API are refused.
     */
    public Map<String, Object> policies(Integer limit, String nextToken, String filter, String q, String sort,
                                        String cloudProvider, String freeText, String status, String debug) {
        if (policy == null) {
            throw new IllegalStateException("no policy settings");
        }
        StringBuilder query = new StringBuilder();
        Shape shape;
        if (policy.api() == PolicyConfig.Api.SCA) {
            if (limit != null || given(nextToken) || given(filter) || given(q) || given(sort)) {
                throw new IllegalArgumentException("the SCA Policies API documents no limit, nextToken, filter, q or "
                        + "sort (its parameters are cloud_provider, free_text, status and debug)");
            }
            param(query, "cloud_provider", cloudProvider);
            param(query, "free_text", freeText);
            param(query, "status", status);
            param(query, "debug", debug);
            shape = new Shape("sca", false, Set.of(HITS), Set.of(TOTAL));
        } else {
            if (given(cloudProvider) || given(freeText) || given(status) || given(debug)) {
                throw new IllegalArgumentException("cloud_provider, free_text, status and debug belong to the SCA "
                        + "Policies API; the configured API is uap (limit, nextToken, filter, q, sort)");
            }
            if (limit != null) {
                if (limit < 1 || limit > PolicyConfig.MAX_PAGE_SIZE) {
                    throw new IllegalArgumentException("limit must be between 1 and " + PolicyConfig.MAX_PAGE_SIZE
                            + " (documented maximum)");
                }
                query.append("limit=").append(limit);
            }
            param(query, "nextToken", nextToken);
            param(query, "filter", filter);
            param(query, "q", q);
            param(query, "sort", sort);
            shape = new Shape("uap", false, Set.of(RESULTS), Set.of(NEXT_TOKEN, TOTAL));
            shape.params.put("limit", limit);
            shape.params.put("nextToken", nextToken);
        }
        URI uri = URI.create(policy.baseUrl() + PolicyClient.POLICIES_PATH + (query.length() == 0 ? "" : "?" + query));
        Map<String, Object> out = start("policies");
        out.put("policy_api", policy.api().name().toLowerCase(java.util.Locale.ROOT));
        out.put("request", request("GET", uri, null));
        return call(out, tokens(Target.POLICIES), HttpRequest.newBuilder(uri).GET(), policy.requestTimeout(), shape);
    }

    private static boolean given(String value) {
        return value != null && !value.isEmpty();
    }

    /** Appends {@code name=value}, URL-encoded, when the value was given. */
    private static void param(StringBuilder query, String name, String value) {
        if (given(value)) {
            query.append(query.length() == 0 ? "" : "&").append(name).append('=').append(encode(value));
        }
    }

    /** Percent-encoding for a query value; a space is sent as {@code %20}, which every server reads as a space. */
    static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    // ---- what each operation's response looks like ----------------------------------------

    static final String SUCCESS = "/success";
    static final String MESSAGE = "/Message";
    static final String REDROCK_ROWS = "/Result/Results";
    static final String REDROCK_COUNT = "/Result/Count";
    static final String REDROCK_FULL_COUNT = "/Result/FullCount";
    static final String PRINCIPALS = "/Result/Principals";
    static final String RESULTS = "/results";
    static final String NEXT_TOKEN = "/nextToken";
    static final String TOTAL = "/total";
    static final String HITS = "/hits";

    /** Which arrays to count and which values to read while the body is checked, and the request's paging values. */
    private static final class Shape {
        final String kind;
        final boolean identityEnvelope;
        final Set<String> counts;
        final Set<String> values;
        final Map<String, Object> params = new HashMap<>();

        Shape(String kind, boolean identityEnvelope, Set<String> counts, Set<String> values) {
            this.kind = kind;
            this.identityEnvelope = identityEnvelope;
            this.counts = counts;
            this.values = values;
        }
    }

    // ---- one request ----------------------------------------------------------------------

    private record Received(int status, java.net.http.HttpHeaders headers, ResponseBody body) {
    }

    /** The body did not arrive completely (connection ended, deadline passed, or a local protection). */
    private static final class IncompleteBody extends RuntimeException {
        final int status;
        final long receivedBytes;
        final String kind;

        IncompleteBody(int status, long receivedBytes, String kind, String message, Throwable cause) {
            super(message, cause);
            this.status = status;
            this.receivedBytes = receivedBytes;
            this.kind = kind;
        }
    }

    /**
     * Sends with the cached token. A 401 renews the token and retries once (a cached token may have been revoked);
     * 403, 429 and every other status are returned as they are, never retried here. {@code timeout} bounds the whole
     * exchange: waiting for the answer and receiving its entire body.
     */
    private Map<String, Object> call(Map<String, Object> out, TokenProvider tokens, HttpRequest.Builder builder,
                                     Duration timeout, Shape shape) {
        long started = System.nanoTime();
        out.put("auth", tokens.requestDescription());
        builder.timeout(timeout).header("Accept", "application/json");
        Received received;
        try {
            received = send(builder, tokens.token(), timeout);
            if (received.status() == 401) {
                received.body().close();
                out.put("retried_after_401", true);
                tokens.invalidate();
                received = send(builder, tokens.token(), timeout);
            }
        } catch (CyberArkApiException e) {
            if (TokenProvider.ENDPOINT.equals(e.endpoint()) || TokenProvider.POLICY_ENDPOINT.equals(e.endpoint())) {
                return tokenFailure(out, e, started);
            }
            out.put("completeness", incomplete(null, "no answer was received"));
            return finish(out, false, e.kind().name(), sanitize(e.getMessage()), started);
        } catch (IncompleteBody e) {
            out.put("http_status", e.status);
            out.put("completeness", incomplete(e.receivedBytes, "the body did not arrive completely, so nothing of it "
                    + "is returned"));
            return finish(out, false, e.kind, sanitize(e.getMessage()), started);
        }
        int status = received.status();
        out.put("http_status", status);
        received.headers().firstValue("Content-Type").ifPresent(ct -> out.put("content_type", ct));
        ResponseInspector.Result inspected;
        try {
            inspected = putBody(out, received.body(), shape);
        } catch (IOException e) {
            received.body().close();
            ResponseBody.release(out);
            out.remove("response");
            out.put("completeness", incomplete(received.body().size(), "the received body could not be processed"));
            // every I/O here is on this service's own temporary file (reading it, or writing the masked copy)
            return finish(out, false, e instanceof ResponseBody.LocalLimitException ? "LOCAL_LIMIT" : "LOCAL_STORAGE",
                    sanitize(e.getMessage()), started);
        }
        if (status < 200 || status > 299) {
            String kind = switch (status) {
                case 401 -> "AUTHENTICATION";
                case 403 -> "AUTHORIZATION";
                case 429 -> "RATE_LIMITED";
                default -> "HTTP_STATUS";
            };
            String error = "CyberArk answered HTTP " + status + "; its body is in the response";
            if (status == 429) {
                java.util.Optional<String> retryAfter = received.headers().firstValue("Retry-After");
                retryAfter.ifPresent(v -> out.put("retry_after", v));
                error = "CyberArk answered HTTP 429 (too many requests); nothing was retried. Send the same request "
                        + "again later" + retryAfter.map(v -> " (Retry-After: " + v + ")").orElse("");
            }
            out.put("completeness", noData(true, "CyberArk answered HTTP " + status));
            return finish(out, false, kind, error, started);
        }
        if (inspected == null) {
            out.put("completeness", noData(true, "the body is empty"));
            return finish(out, false, "INVALID_RESPONSE", "HTTP " + status + " with an empty body", started);
        }
        switch (inspected.outcome()) {
            case NOT_JSON -> {
                out.put("completeness", noData(true, "the body is not JSON"));
                return finish(out, false, "INVALID_RESPONSE", "HTTP " + status + " but the body is not JSON", started);
            }
            case PARSER_LIMIT -> {
                out.put("completeness", noData(true, "the body could not be checked"));
                return finish(out, false, "PARSER_LIMIT", sanitize(inspected.error()), started);
            }
            default -> {
                // JSON or DUPLICATE_KEYS: valid JSON
            }
        }
        if (shape.identityEnvelope) {
            JsonNode success = inspected.value(SUCCESS);
            if (success != null && success.isBoolean() && !success.asBoolean()) {
                JsonNode message = inspected.value(MESSAGE);
                out.put("completeness", noData(true, "CyberArk answered success=false"));
                return finish(out, false, "API_FAILURE", "success=false"
                        + (message == null || message.isNull() ? "" : ": " + sanitize(message.asText())), started);
            }
        }
        out.put("completeness", completeness(shape, inspected));
        return finish(out, true, null, null, started);
    }

    private static final ScheduledExecutorService DEADLINES = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "cyberark-response-deadline");
        t.setDaemon(true);
        return t;
    });

    /**
     * One request. The status and headers must arrive within {@code timeout} (HttpClient's request timeout); the body
     * is then received into a {@link ResponseBody} within what is left of the same {@code timeout}. Java's request
     * timeout alone does not cover the body (checked: a body that trickled in for 6 s was accepted with a 2 s timeout),
     * so a deadline stops a body that is still arriving when the time is up.
     */
    private Received send(HttpRequest.Builder builder, String token, Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        HttpRequest request = builder.copy().setHeader("Authorization", "Bearer " + token).build();
        HttpResponse<InputStream> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
        } catch (IOException e) {
            throw new CyberArkApiException(CyberArkApiException.Kind.TRANSPORT, "request", null,
                    e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage()), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new CyberArkApiException(CyberArkApiException.Kind.TRANSPORT, "request", null, "interrupted", e);
        }
        int status = response.statusCode();
        ResponseBody.Writer writer = new ResponseBody.Writer(spool);
        Deadline watch = new Deadline(Thread.currentThread(), response.body(),
                Math.max(1, deadline - System.nanoTime()));
        try (writer; InputStream in = response.body()) {
            in.transferTo(writer);
            ResponseBody body = writer.finish();
            if (watch.stop()) { // the deadline fired just as the last byte arrived: treat as late
                body.close();
                throw new IOException("deadline");
            }
            return new Received(status, response.headers(), body);
        } catch (IOException e) {
            boolean late = watch.stop();
            if (e instanceof ResponseBody.LocalLimitException) {
                throw new IncompleteBody(status, writer.size(), "LOCAL_LIMIT", e.getMessage(), e);
            }
            if (e instanceof ResponseBody.LocalStorageException && !late) {
                throw new IncompleteBody(status, writer.size(), "LOCAL_STORAGE", e.getMessage()
                        + " (a local disk problem of this service, not a network or CyberArk failure)", e);
            }
            if (late) {
                throw new IncompleteBody(status, writer.size(), "TRANSPORT", "HttpTimeoutException: the whole body "
                        + "did not arrive within " + timeout.toSeconds() + " s (" + writer.size() + " bytes received)",
                        e);
            }
            throw new IncompleteBody(status, writer.size(), "TRANSPORT", "the connection ended before the whole body "
                    + "arrived (" + writer.size() + " bytes received): " + e.getClass().getSimpleName()
                    + (e.getMessage() == null ? "" : ": " + e.getMessage()), e);
        } finally {
            watch.stop();
        }
    }

    /** Stops a body that is still arriving at the deadline: interrupts the reading thread and closes the stream. */
    private static final class Deadline {
        private final Thread reader;
        private final InputStream in;
        private final java.util.concurrent.ScheduledFuture<?> task;
        private int state; // 0 running, 1 done, 2 fired

        Deadline(Thread reader, InputStream in, long nanos) {
            this.reader = reader;
            this.in = in;
            this.task = DEADLINES.schedule(this::fire, nanos, TimeUnit.NANOSECONDS);
        }

        private void fire() {
            synchronized (this) {
                if (state != 0) {
                    return;
                }
                state = 2;
                reader.interrupt();
            }
            try {
                in.close();
            } catch (IOException ignored) {
                // the interrupt already stops the read
            }
        }

        /** Ends the watch; returns whether the deadline fired (its interrupt is then cleared from this thread). */
        boolean stop() {
            synchronized (this) {
                if (state == 0) {
                    state = 1;
                }
            }
            task.cancel(false);
            if (state == 2) {
                Thread.interrupted();
                return true;
            }
            return false;
        }
    }

    private Map<String, Object> tokenFailure(Map<String, Object> out, CyberArkApiException e, long started) {
        out.put("stage", "token");
        out.put("http_status", e.httpStatus());
        if (e.responseBody() != null) {
            putTokenBody(out, e.responseBody());
        }
        out.put("completeness", noData(e.responseBody() != null, "the token request failed, so the API was not called"));
        return finish(out, false, e.kind().name(), sanitize(e.getMessage()), started);
    }

    // ---- envelope -------------------------------------------------------------------------

    private static Map<String, Object> start(String operation) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("operation", operation);
        return out;
    }

    private static Map<String, Object> request(String method, URI uri, JsonNode body) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("method", method);
        r.put("url", uri.toString());
        if (body != null) {
            r.put("body", body);
        }
        return r;
    }

    /** The token answer (small, kept in memory): parsed when JSON, otherwise text; our own secrets masked. */
    private void putTokenBody(Map<String, Object> out, String raw) {
        if (raw == null || raw.isEmpty()) {
            out.put("response", null);
            return;
        }
        String body = mask(raw, out);
        try {
            out.put("response", EXACT.readTree(body));
        } catch (JsonProcessingException e) {
            out.put("response_text", body);
        }
    }

    /**
     * Puts CyberArk's body into the envelope after one streaming check ({@link ResponseInspector}): valid JSON goes
     * under {@code response} with its bytes unchanged; JSON with a repeated key goes under {@code response_text} (so no
     * value is lost) with {@code duplicate_keys}; anything else under {@code response_text}. If one of this service's
     * own credentials or tokens appears in it, a masked copy is returned instead and {@code masked} is set.
     * Returns the inspection, or {@code null} for an empty body.
     */
    private ResponseInspector.Result putBody(Map<String, Object> out, ResponseBody body, Shape shape)
            throws IOException {
        out.put("response_bytes", body.size());
        if (body.size() == 0) {
            body.close();
            out.put("response", null);
            return null;
        }
        List<String> secrets = secrets();
        ResponseInspector.Result result = ResponseInspector.inspect(body, shape.counts, shape.values, secrets);
        switch (result.outcome()) {
            case JSON -> {
                if (result.secretFound()) {
                    ResponseBody masked;
                    try {
                        masked = ResponseInspector.maskedCopy(body, secrets, spool);
                    } finally {
                        body.close();
                    }
                    out.put("masked", true);
                    out.put("response", masked);
                } else {
                    out.put("response", body);
                }
            }
            case DUPLICATE_KEYS -> {
                out.put("response_text", textOf(body, out, result.secretFound()));
                out.put("duplicate_keys", true); // valid JSON; kept as text so no value is lost
            }
            default -> out.put("response_text", textOf(body, out, true));
        }
        return result;
    }

    /**
     * The body as {@code response_text}: a string when it is small or must be masked, otherwise the body itself,
     * written as a JSON string from its file.
     */
    private Object textOf(ResponseBody body, Map<String, Object> out, boolean mayHoldSecret) throws IOException {
        if (!body.spooled() || mayHoldSecret) {
            try {
                return mask(body.readText(), out);
            } finally {
                body.close();
            }
        }
        return body.asText();
    }

    // ---- completeness ----------------------------------------------------------------------

    /**
     * What this one response says about completeness, kept apart on purpose:
     * <ul>
     *   <li>{@code response_complete}: the whole HTTP body arrived (says nothing about other pages)</li>
     *   <li>{@code records_in_response}: the records counted in this body (rows, policies, hits, principals)</li>
     *   <li>{@code more_available}: true / false / null (= cannot be told from this response); {@code basis} says
     *       why, and {@code next_request} gives the values for the next page when there is one</li>
     *   <li>{@code all_records_in_this_response}: true only when this one body holds the entire result of the query;
     *       a last page reached by continuing is {@code false} (the earlier pages hold the rest)</li>
     * </ul>
     * Nothing here is fetched or computed beyond this body; CyberArk's own counts are copied under
     * {@code reported_by_cyberark}.
     */
    private static Map<String, Object> completeness(Shape shape, ResponseInspector.Result r) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("response_complete", true);
        Map<String, Object> reported = new LinkedHashMap<>();
        switch (shape.kind) {
            case "redrock" -> redrockCompleteness(shape, r, c, reported);
            case "uap" -> uapCompleteness(shape, r, c, reported);
            case "sca" -> {
                Long hits = r.count(HITS);
                JsonNode total = r.value(TOTAL);
                putReported(reported, "total", total);
                c.put("paged", false);
                c.put("records_in_response", hits);
                if (hits != null && total != null && total.isIntegralNumber() && hits < total.longValue()) {
                    c.put("more_available", null);
                    c.put("all_records_in_this_response", false);
                    c.put("cyberark_limit_suspected", true);
                    c.put("basis", "not paged, but CyberArk's total (" + total.asText() + ") is larger than the hits "
                            + "returned (" + hits + "); the SCA Policies API documents no paging to get the rest");
                } else {
                    c.put("more_available", false);
                    c.put("all_records_in_this_response", hits != null);
                    c.put("basis", "the SCA Policies API is not paged (documented); "
                            + (total == null ? "no total to cross-check" : "total matches the hits returned"));
                }
            }
            case "role" -> {
                c.put("paged", false);
                boolean suppressed = Boolean.TRUE.equals(shape.params.get("SuppressPrincipalsList"));
                Long principals = r.count(PRINCIPALS);
                c.put("records_in_response", suppressed ? null : principals);
                c.put("more_available", false);
                c.put("all_records_in_this_response", true);
                c.put("basis", "GetRole is not paged (Roles API documents no paging): the whole role is in this "
                        + "response" + (suppressed ? "; principals left out as requested (SuppressPrincipalsList=true)"
                        : "; records = entries in Result.Principals"));
            }
            default -> {
                // no paging information for this operation
            }
        }
        if (!reported.isEmpty()) {
            c.put("reported_by_cyberark", reported);
        }
        return c;
    }

    private static void redrockCompleteness(Shape shape, ResponseInspector.Result r, Map<String, Object> c,
                                            Map<String, Object> reported) {
        Long rows = r.count(REDROCK_ROWS);
        JsonNode fullCount = r.value(REDROCK_FULL_COUNT);
        putReported(reported, "Count", r.value(REDROCK_COUNT));
        putReported(reported, "FullCount", fullCount);
        Integer pageNumber = (Integer) shape.params.get("pageNumber");
        Integer pageSize = (Integer) shape.params.get("pageSize");
        Integer limit = (Integer) shape.params.get("limit");
        c.put("paged", true);
        c.put("records_in_response", rows);
        if (rows == null) {
            c.put("more_available", null);
            c.put("all_records_in_this_response", null);
            c.put("basis", "no Result.Results array in the response");
            return;
        }
        if (pageSize == null) {
            c.put("more_available", null);
            c.put("all_records_in_this_response", null);
            c.put("basis", "no PageSize was sent and CyberArk does not document its default page size, so this "
                    + "response cannot tell whether more rows exist; send pageNumber and pageSize to page explicitly");
            return;
        }
        int expected = limit != null ? Math.min(pageSize, limit) : pageSize;
        boolean firstPage = pageNumber == null || pageNumber <= 1;
        if (rows < expected) {
            long before = firstPage ? 0 : (long) (pageNumber - 1) * pageSize;
            if (fullCount != null && fullCount.isIntegralNumber() && before + rows < fullCount.longValue()) {
                c.put("more_available", null);
                c.put("all_records_in_this_response", false);
                c.put("cyberark_limit_suspected", true);
                c.put("basis", "a short page (" + rows + " of " + expected + " rows) normally ends the data, but "
                        + "CyberArk's FullCount (" + fullCount.asText() + ") is larger than the rows up to this page; "
                        + "CyberArk may cap the page size. Use a smaller pageSize and compare");
                return;
            }
            c.put("more_available", false);
            c.put("all_records_in_this_response", firstPage);
            c.put("basis", "short page: fewer rows (" + rows + ") than requested (" + expected + "), so this is the "
                    + "last page (the end rule of CyberArk's official SDK; Redrock documents no other end marker)"
                    + (firstPage ? "" : "; earlier pages hold the other rows"));
            return;
        }
        if (limit != null && rows > limit) {
            // CyberArk sent more rows than the Limit we sent, so it did not apply Limit the way it is documented.
            // How it paged this response is then unknown, so nothing is concluded and no next page is suggested.
            c.put("more_available", null);
            c.put("all_records_in_this_response", null);
            c.put("rows_exceed_limit", true);
            c.put("basis", "the response has " + rows + " rows, more than the limit sent (" + limit + "): CyberArk "
                    + "did not apply Limit as the documented maximum for the page. Whether more rows exist cannot be "
                    + "told, and no next page is suggested because the paging CyberArk applied is unclear. Request "
                    + "again without limit (pageSize alone) to page reliably");
            return;
        }
        c.put("more_available", null);
        c.put("all_records_in_this_response", firstPage ? null : false);
        if (limit != null && limit < pageSize) {
            // Redrock documents Limit as "the maximum results for the specified page", while CyberArk's official SDK
            // sends it as a cap on the total. Either way, the next PageNumber with this PageSize could start after
            // rows this response left out (limit+1 .. pageSize of this page), so no next page is suggested.
            c.put("basis", rows + " rows = the limit sent (" + limit + "), which is smaller than pageSize (" + pageSize + "). "
                    + "More rows may exist, but requesting the next pageNumber with this pageSize could skip the rows "
                    + "between them (Limit's exact paging behaviour is not fully documented). To page without gaps, "
                    + "send pageSize equal to the number of rows wanted and no smaller limit");
            return;
        }
        c.put("basis", "full page (" + rows + " rows): more rows may exist. Request the next page; a short or empty "
                + "page means the end");
        if (pageNumber != null) {
            Map<String, Object> next = new LinkedHashMap<>();
            next.put("pageNumber", pageNumber + 1);
            next.put("pageSize", pageSize);
            if (limit != null) {
                next.put("limit", limit);
            }
            c.put("next_request", next);
        }
    }

    private static void uapCompleteness(Shape shape, ResponseInspector.Result r, Map<String, Object> c,
                                        Map<String, Object> reported) {
        Long results = r.count(RESULTS);
        JsonNode token = r.value(NEXT_TOKEN);
        JsonNode total = r.value(TOTAL);
        putReported(reported, "total", total);
        boolean continued = given((String) shape.params.get("nextToken"));
        c.put("paged", true);
        c.put("records_in_response", results);
        boolean more = token != null && token.isTextual() && !token.asText().isEmpty();
        if (more) {
            c.put("more_available", true);
            c.put("all_records_in_this_response", false);
            c.put("basis", "CyberArk returned a nextToken (documented continuation token)");
            Map<String, Object> next = new LinkedHashMap<>();
            next.put("nextToken", token.asText());
            if (shape.params.get("limit") != null) {
                next.put("limit", shape.params.get("limit"));
            }
            next.put("note", "send the same limit, filter, q and sort with this nextToken");
            c.put("next_request", next);
            return;
        }
        String ending = token == null || token.isNull() ? "no nextToken" : "an empty nextToken";
        if (!continued && results != null && total != null && total.isIntegralNumber()
                && results < total.longValue()) {
            c.put("more_available", null);
            c.put("all_records_in_this_response", false);
            c.put("cyberark_limit_suspected", true);
            c.put("basis", ending + ", but CyberArk's total (" + total.asText() + ") is larger than the results "
                    + "returned (" + results + ")");
            return;
        }
        c.put("more_available", false);
        c.put("all_records_in_this_response", !continued && results != null);
        c.put("basis", ending + ": this is the last page" + (continued ? "; earlier pages hold the other policies"
                : ""));
    }

    private static void putReported(Map<String, Object> reported, String name, JsonNode value) {
        if (value != null) {
            reported.put(name, value);
        }
    }

    private static Map<String, Object> noData(boolean bodyComplete, String reason) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("response_complete", bodyComplete);
        c.put("records_in_response", null);
        c.put("more_available", null);
        c.put("all_records_in_this_response", null);
        c.put("basis", "no data: " + reason);
        return c;
    }

    private static Map<String, Object> incomplete(Long receivedBytes, String reason) {
        Map<String, Object> c = noData(false, reason);
        if (receivedBytes != null) {
            c.put("received_bytes", receivedBytes);
        }
        return c;
    }

    private static Map<String, Object> finish(Map<String, Object> out, boolean ok, String kind, String error,
                                              long started) {
        out.put("ok", ok);
        out.put("status", ok ? "SUCCESS" : "FAILED");
        if (!ok) {
            out.put("error_kind", kind);
            out.put("error", error);
        }
        out.put("duration_ms", (System.nanoTime() - started) / 1_000_000);
        return out;
    }

    // ---- secrets --------------------------------------------------------------------------

    /** Every value of ours that must never be shown: client secrets, Basic-auth values, issued tokens. */
    private List<String> sensitive() {
        List<String> values = new ArrayList<>();
        if (identity != null) {
            values.add(identity.clientSecret());
        }
        if (policy != null) {
            values.add(policy.clientSecret());
        }
        for (TokenProvider t : new TokenProvider[] {identityTokens, policyTokens}) {
            if (t != null) {
                values.add(t.basicValue());
                values.addAll(t.issuedTokens());
            }
        }
        return values;
    }

    /** Our own values that are long enough to be searched for in a body. */
    private List<String> secrets() {
        List<String> values = new ArrayList<>();
        for (String value : sensitive()) {
            if (value != null && value.length() >= 4 && !values.contains(value)) {
                values.add(value);
            }
        }
        return values;
    }

    /** Replaces our own credentials and tokens in CyberArk's body; nothing else is changed. */
    private String mask(String body, Map<String, Object> out) {
        String result = body;
        for (String value : sensitive()) {
            if (value != null && value.length() >= 4 && result.contains(value)) {
                result = result.replace(value, MASK);
                out.put("masked", true);
            }
        }
        return result;
    }

    /** For our own messages (not CyberArk's body): masks the known values and anything that looks like a secret. */
    public String sanitize(String text) {
        return ErrorSanitizer.clean(text, sensitive());
    }

    private synchronized TokenProvider tokens(Target target) {
        if (target == Target.IDENTITY) {
            requireIdentity();
            if (identityTokens == null) {
                identityTokens = new TokenProvider(identity, http, Clock.systemUTC());
            }
            return identityTokens;
        }
        if (policy == null) {
            throw new IllegalStateException("no policy settings");
        }
        if (policyTokens == null) {
            policyTokens = new TokenProvider(policy, http, Clock.systemUTC());
        }
        return policyTokens;
    }

    private void requireIdentity() {
        if (identity == null) {
            throw new IllegalStateException("no Identity settings");
        }
    }
}
