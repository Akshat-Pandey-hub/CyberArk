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
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
 * CyberArk's body under {@code response} (parsed with exact numbers and the original field order) or, when it is not
 * JSON, under {@code response_text} exactly as received. The only change ever made to CyberArk's body is replacing
 * this service's own credentials and tokens with {@code ***} if they appear in it; {@code masked} says when that
 * happened. A 401 renews the token and retries once; any other status is returned as it is, never as an empty
 * success.
 */
public final class CloudApi {

    public enum Target { IDENTITY, POLICIES }

    static final String MASK = "***";

    /** Keeps numbers exactly as written (no double rounding) and rejects duplicate keys instead of dropping one. */
    private static final ObjectMapper EXACT = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
            .nodeFactory(JsonNodeFactory.withExactBigDecimals(true))
            .build();

    private final CyberArkConfig identity;
    private final PolicyConfig policy;
    private final HttpClient http;
    private TokenProvider identityTokens;
    private TokenProvider policyTokens;

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
        putBody(out, raw);
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
        return call(out, tokens(Target.IDENTITY), builder, identity.redrockTimeout(), true);
    }

    /** GetRole. The role UUID goes in the {@code Name} query parameter (Roles API OpenAPI file). */
    public Map<String, Object> role(String roleId) {
        requireIdentity();
        if (roleId == null || roleId.isBlank()) {
            throw new IllegalArgumentException("id (the role UUID) is required");
        }
        URI uri = URI.create(identity.identityBaseUrl() + CyberArkClient.GET_ROLE_PATH + "?Name="
                + encode(roleId.trim()));
        Map<String, Object> out = start("role");
        out.put("request", request("POST", uri, null));
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).POST(HttpRequest.BodyPublishers.noBody());
        return call(out, tokens(Target.IDENTITY), builder, identity.requestTimeout(), true);
    }

    /**
     * One page of policies. UAP: the documented {@code limit} (1-50), {@code nextToken}, {@code filter}, {@code q} and
     * {@code sort} are each sent only when given, URL-encoded and otherwise unchanged; CyberArk filters, sorts and pages
     * on its side, and nothing is filtered here. SCA (when configured): that API documents none of these, so none is
     * accepted.
     */
    public Map<String, Object> policies(Integer limit, String nextToken, String filter, String q, String sort) {
        if (policy == null) {
            throw new IllegalStateException("no policy settings");
        }
        StringBuilder query = new StringBuilder();
        if (policy.api() == PolicyConfig.Api.SCA) {
            if (limit != null || given(nextToken) || given(filter) || given(q) || given(sort)) {
                throw new IllegalArgumentException("the SCA Policies API documents no limit, nextToken, filter, q or "
                        + "sort");
            }
        } else {
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
        }
        URI uri = URI.create(policy.baseUrl() + PolicyClient.POLICIES_PATH + (query.length() == 0 ? "" : "?" + query));
        Map<String, Object> out = start("policies");
        out.put("policy_api", policy.api().name().toLowerCase(java.util.Locale.ROOT));
        out.put("request", request("GET", uri, null));
        return call(out, tokens(Target.POLICIES), HttpRequest.newBuilder(uri).GET(), policy.requestTimeout(), false);
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

    // ---- one request ----------------------------------------------------------------------

    /**
     * Sends with the cached token. A 401 renews the token and retries once (a cached token may have been revoked);
     * 403 and every other status are returned as they are.
     */
    private Map<String, Object> call(Map<String, Object> out, TokenProvider tokens, HttpRequest.Builder builder,
                                     Duration timeout, boolean identityEnvelope) {
        long started = System.nanoTime();
        out.put("auth", tokens.requestDescription());
        builder.timeout(timeout).header("Accept", "application/json");
        HttpResponse<String> response;
        try {
            response = send(builder, tokens.token());
            if (response.statusCode() == 401) {
                out.put("retried_after_401", true);
                tokens.invalidate();
                response = send(builder, tokens.token());
            }
        } catch (CyberArkApiException e) {
            if (TokenProvider.ENDPOINT.equals(e.endpoint()) || TokenProvider.POLICY_ENDPOINT.equals(e.endpoint())) {
                return tokenFailure(out, e, started);
            }
            return finish(out, false, e.kind().name(), sanitize(e.getMessage()), started);
        }
        int status = response.statusCode();
        out.put("http_status", status);
        response.headers().firstValue("Content-Type").ifPresent(ct -> out.put("content_type", ct));
        putBody(out, response.body());
        if (status < 200 || status > 299) {
            String kind = status == 401 ? "AUTHENTICATION" : status == 403 ? "AUTHORIZATION" : "HTTP_STATUS";
            return finish(out, false, kind, "CyberArk answered HTTP " + status + "; its body is in the response",
                    started);
        }
        if (out.containsKey("response") && out.get("response") == null) {
            return finish(out, false, "INVALID_RESPONSE", "HTTP " + status + " with an empty body", started);
        }
        if (out.containsKey("response_text") && !Boolean.TRUE.equals(out.get("duplicate_keys"))) {
            return finish(out, false, "INVALID_RESPONSE", "HTTP " + status + " but the body is not JSON", started);
        }
        if (identityEnvelope && out.get("response") instanceof JsonNode node && node.isObject()) {
            JsonNode success = node.get("success");
            if (success != null && success.isBoolean() && !success.asBoolean()) {
                JsonNode message = node.get("Message");
                return finish(out, false, "API_FAILURE", "success=false"
                        + (message == null || message.isNull() ? "" : ": " + sanitize(message.asText())), started);
            }
        }
        return finish(out, true, null, null, started);
    }

    private HttpResponse<String> send(HttpRequest.Builder builder, String token) {
        HttpRequest request = builder.copy().setHeader("Authorization", "Bearer " + token).build();
        try {
            return http.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new CyberArkApiException(CyberArkApiException.Kind.TRANSPORT, "request", null,
                    e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage()), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new CyberArkApiException(CyberArkApiException.Kind.TRANSPORT, "request", null, "interrupted", e);
        }
    }

    private Map<String, Object> tokenFailure(Map<String, Object> out, CyberArkApiException e, long started) {
        out.put("stage", "token");
        out.put("http_status", e.httpStatus());
        if (e.responseBody() != null) {
            putBody(out, e.responseBody());
        }
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

    /**
     * Puts CyberArk's body into the envelope after masking this service's own credentials and tokens: parsed when it
     * is JSON (exact numbers, original order), otherwise as text. A body with duplicate keys is kept as text so that
     * nothing is dropped.
     */
    private void putBody(Map<String, Object> out, String raw) {
        if (raw == null || raw.isEmpty()) {
            out.put("response", null);
            return;
        }
        String body = mask(raw, out);
        try {
            out.put("response", EXACT.readTree(body));
        } catch (JsonProcessingException e) {
            out.put("response_text", body);
            if (e.getMessage() != null && e.getMessage().startsWith("Duplicate field")) {
                out.put("duplicate_keys", true); // valid JSON; kept as text so no value is lost
            }
        }
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
