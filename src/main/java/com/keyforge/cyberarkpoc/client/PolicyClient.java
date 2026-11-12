package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.config.PolicyConfig;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Read-only client for the policy list of Use Case 2, authenticated with the custom OAuth2 token
 * ({@link TokenProvider.Style#CUSTOM_OAUTH2}). Contract: docs/API_CONTRACT.md, Use Case 2.
 *
 * <ul>
 *   <li>UAP, {@code GET <base>/policies?limit=&nextToken=}: response {@code {"results": [..], "nextToken", "total"}};
 *       every page is read until {@code nextToken} is absent or empty</li>
 *   <li>SCA, {@code GET <base>/policies}: response {@code {"total", "hits": [..]}}; no paging is documented</li>
 * </ul>
 * A failed call throws {@link CyberArkApiException}. Anything that leaves the completeness of the list in doubt
 * (a repeated {@code nextToken}, a {@code total} that does not match, no {@code total}, a non-empty
 * {@code failedServices}, the page limit) is returned as {@code complete = false} with a note, never as a full list.
 */
public final class PolicyClient {

    public static final String POLICIES_PATH = "/policies";
    static final String ENDPOINT = "policies";

    /**
     * The policies read, each a JSON object exactly as returned (secrets removed).
     *
     * @param reportedTotal the {@code total} of the last page, or {@code null} if the API sent none
     * @param notes         why the list is not known to be complete
     */
    public record Listing(List<JsonNode> policies, boolean complete, int pages, Integer reportedTotal,
                          List<String> notes) {
    }

    private final PolicyConfig config;
    private final HttpClient http;
    private final TokenProvider tokens;

    public PolicyClient(PolicyConfig config) {
        this(config, HttpClient.newBuilder()
                .connectTimeout(config.requestTimeout())
                .followRedirects(HttpClient.Redirect.NEVER)
                .build());
    }

    public PolicyClient(PolicyConfig config, HttpClient http) {
        this.config = config;
        this.http = http;
        this.tokens = new TokenProvider(config, http, Clock.systemUTC());
    }

    public PolicyConfig.Api api() {
        return config.api();
    }

    public Listing listPolicies() {
        return config.api() == PolicyConfig.Api.SCA ? listSca() : listUap();
    }

    private Listing listUap() {
        List<JsonNode> policies = new ArrayList<>();
        List<String> notes = new ArrayList<>();
        Set<String> seenTokens = new HashSet<>();
        boolean complete = true;
        Integer total = null;
        String nextToken = null;
        int pages = 0;
        while (true) {
            if (pages >= config.maxPages()) {
                complete = false;
                notes.add("stopped after " + pages + " pages (safety limit); more policies may exist");
                break;
            }
            String query = "?limit=" + config.pageSize()
                    + (nextToken == null ? "" : "&nextToken=" + URLEncoder.encode(nextToken, StandardCharsets.UTF_8));
            JsonNode root = get(URI.create(config.baseUrl() + POLICIES_PATH + query));
            pages++;
            addAll(policies, root, "results");
            total = intOrNull(root.get("total"), total);
            JsonNode failed = root.get("failedServices");
            if (failed != null && failed.isArray() && !failed.isEmpty()) {
                complete = false;
                notes.add("page " + pages + " lists failedServices " + Json.snippet(failed.toString())
                        + ": policies of those services may be missing");
            }
            String next = Json.text(root, "nextToken");
            if (next == null || next.isBlank()) {
                break;
            }
            if (!seenTokens.add(next)) {
                complete = false;
                notes.add("nextToken repeated on page " + pages + "; paging stopped to avoid an endless loop");
                break;
            }
            nextToken = next;
        }
        complete &= checkTotal(policies.size(), total, notes);
        return new Listing(List.copyOf(policies), complete, pages, total, List.copyOf(notes));
    }

    private Listing listSca() {
        JsonNode root = get(URI.create(config.baseUrl() + POLICIES_PATH));
        List<JsonNode> policies = new ArrayList<>();
        addAll(policies, root, "hits");
        List<String> notes = new ArrayList<>();
        Integer total = intOrNull(root.get("total"), null);
        boolean complete = checkTotal(policies.size(), total, notes);
        return new Listing(List.copyOf(policies), complete, 1, total, List.copyOf(notes));
    }

    /** {@code total} is required by both references; without it, or when it differs, completeness is unknown. */
    private static boolean checkTotal(int received, Integer total, List<String> notes) {
        if (total == null) {
            notes.add("the API reported no 'total', so it cannot be shown that every policy was received");
            return false;
        }
        if (total != received) {
            notes.add("the API reported total " + total + " but " + received + " policies were received");
            return false;
        }
        return true;
    }

    private static void addAll(List<JsonNode> into, JsonNode root, String field) {
        JsonNode items = root.get(field);
        if (items == null || !items.isArray()) {
            throw new CyberArkApiException(CyberArkApiException.Kind.INVALID_RESPONSE, ENDPOINT, 200,
                    "missing array '" + field + "'");
        }
        for (JsonNode item : items) {
            if (!item.isObject()) {
                throw new CyberArkApiException(CyberArkApiException.Kind.INVALID_RESPONSE, ENDPOINT, 200,
                        "an item of '" + field + "' is not a JSON object");
            }
            into.add(SecretRedactor.redact(item).value());
        }
    }

    private static Integer intOrNull(JsonNode value, Integer fallback) {
        return value != null && value.isIntegralNumber() && value.canConvertToInt()
                ? Integer.valueOf(value.asInt()) : fallback;
    }

    /**
     * Masks the client secret, its Basic-auth form and every access token this client received, then applies
     * {@link ErrorSanitizer}. Use it on any text that leaves the service.
     */
    public String sanitize(String text) {
        List<String> sensitive = new ArrayList<>(tokens.issuedTokens());
        sensitive.add(config.clientSecret());
        sensitive.add(Base64.getEncoder().encodeToString(
                (config.clientId() + ":" + config.clientSecret()).getBytes(StandardCharsets.UTF_8)));
        return ErrorSanitizer.clean(text, sensitive);
    }

    /** GET with the cached token; on 401 the token is renewed and the call retried once. */
    private JsonNode get(URI uri) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .timeout(config.requestTimeout())
                .header("Accept", "application/json")
                .GET();
        HttpResponse<String> response = send(builder, tokens.token());
        if (response.statusCode() == 401) {
            tokens.invalidate();
            response = send(builder, tokens.token());
        }
        int status = response.statusCode();
        if (status == 401 || status == 403) {
            throw new CyberArkApiException(CyberArkApiException.Kind.AUTHENTICATION, ENDPOINT, status,
                    status == 401 ? "token not accepted" : "the OAuth2 app or service user lacks permission");
        }
        if (status < 200 || status > 299) {
            throw new CyberArkApiException(CyberArkApiException.Kind.HTTP_STATUS, ENDPOINT, status,
                    Json.snippet(response.body()));
        }
        JsonNode root = Json.parse(ENDPOINT, status, response.body());
        if (!root.isObject()) {
            throw new CyberArkApiException(CyberArkApiException.Kind.INVALID_RESPONSE, ENDPOINT, status,
                    "response is not a JSON object");
        }
        return root;
    }

    private HttpResponse<String> send(HttpRequest.Builder builder, String token) {
        HttpRequest request = builder.copy().setHeader("Authorization", "Bearer " + token).build();
        try {
            return http.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new CyberArkApiException(CyberArkApiException.Kind.TRANSPORT, ENDPOINT, null,
                    e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage()), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new CyberArkApiException(CyberArkApiException.Kind.TRANSPORT, ENDPOINT, null, "interrupted", e);
        }
    }
}
