package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.config.CyberArkConfig;
import com.keyforge.cyberarkpoc.model.CyberArkUser;
import com.keyforge.cyberarkpoc.model.Policy;
import com.keyforge.cyberarkpoc.model.Role;
import com.keyforge.cyberarkpoc.model.RoleDetails;
import com.keyforge.cyberarkpoc.model.RoleMember;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Read-only client for the CyberArk calls the two use cases need. Endpoint paths and response
 * fields follow docs/API_CONTRACT.md, where each one is marked verified or assumed.
 *
 * <p>Every failure is thrown as {@link CyberArkApiException}; nothing is swallowed, so a caller can
 * never mistake a failed call for an empty result.
 */
public final class CyberArkClient {

    public static final String REDROCK_PATH = "/Redrock/query";
    public static final String GET_ROLE_PATH = "/Roles/GetRole";
    public static final String GET_ROLE_MEMBERS_PATH = "/Roles/GetRoleMembers";
    public static final String POLICIES_PATH = "/policies";
    /** The SDK's default page size for policies. */
    public static final int POLICY_PAGE_LIMIT = 50;

    private final CyberArkConfig config;
    private final HttpClient http;
    private final TokenProvider tokens;

    public CyberArkClient(CyberArkConfig config) {
        this(config, HttpClient.newBuilder()
                .connectTimeout(config.requestTimeout())
                .followRedirects(HttpClient.Redirect.NEVER)
                .build());
    }

    public CyberArkClient(CyberArkConfig config, HttpClient http) {
        this.config = config;
        this.http = http;
        this.tokens = new TokenProvider(config, http, Clock.systemUTC());
    }

    /** Roles whose name matches a Redrock {@code LIKE} pattern, e.g. {@code APP-CYA-ISPSS-SCA-AWS-%-BUApprovers}. */
    public List<Role> findRolesByNamePattern(String likePattern) {
        String script = "SELECT ID, Name, Description FROM Role WHERE Name LIKE '" + sqlLiteral(likePattern) + "'";
        return IdentityResponses.roles("Redrock/query (Role)", redrock(script));
    }

    /** GetRole. The role UUID goes in the {@code Name} query parameter (official Roles API reference). */
    public RoleDetails getRole(String roleId) {
        URI uri = URI.create(config.identityBaseUrl() + GET_ROLE_PATH + "?Name=" + urlEncode(roleId));
        JsonNode root = sendJson("Roles/GetRole", authorized(uri).POST(HttpRequest.BodyPublishers.noBody()));
        return IdentityResponses.roleDetails("Roles/GetRole", root);
    }

    /**
     * GetRoleMembers. The official reference passes the role UUID as the {@code name} query parameter;
     * the official SDK sends it as {@code {"Name": ..}} in the body. Both are sent.
     */
    public List<RoleMember> getRoleMembers(String roleId) {
        URI uri = URI.create(config.identityBaseUrl() + GET_ROLE_MEMBERS_PATH + "?name=" + urlEncode(roleId));
        JsonNode root = sendJson("Roles/GetRoleMembers", jsonPost(uri, Map.of("Name", roleId)));
        return IdentityResponses.roleMembers("Roles/GetRoleMembers", root);
    }

    /** The user with this id, or empty when the User table has no such row. */
    public Optional<CyberArkUser> findUserById(String userId) {
        String script = "SELECT ID, Username, DisplayName, Email, LastLogin, Status, StatusEnum FROM User WHERE ID='"
                + sqlLiteral(userId) + "'";
        List<CyberArkUser> users = IdentityResponses.users("Redrock/query (User)", redrock(script));
        if (users.size() > 1) {
            throw new CyberArkApiException(CyberArkApiException.Kind.INVALID_RESPONSE, "Redrock/query (User)", 200,
                    users.size() + " users share the id " + userId);
        }
        return users.stream().findFirst();
    }

    /** Every policy, following {@code nextToken} until the last page. */
    public List<Policy> listPolicies() {
        List<Policy> all = new ArrayList<>();
        Set<String> seenTokens = new HashSet<>();
        String nextToken = null;
        do {
            String query = "?limit=" + POLICY_PAGE_LIMIT + (nextToken == null ? "" : "&nextToken=" + urlEncode(nextToken));
            URI uri = URI.create(config.uapBaseUrl() + POLICIES_PATH + query);
            JsonNode root = sendJson("policies", authorized(uri).GET());
            PolicyResponses.Page page = PolicyResponses.page("policies", root);
            all.addAll(page.policies());
            nextToken = page.nextToken();
            if (nextToken != null && !seenTokens.add(nextToken)) {
                throw new CyberArkApiException(CyberArkApiException.Kind.PAGINATION, "policies", 200,
                        "nextToken repeated; stopping to avoid an endless loop");
            }
        } while (nextToken != null);
        return all;
    }

    /** POST {@code {"Script": ...}} to Redrock and return the raw response. */
    JsonNode redrock(String script) {
        URI uri = URI.create(config.identityBaseUrl() + REDROCK_PATH);
        return sendJson("Redrock/query", jsonPost(uri, Map.of("Script", script)));
    }

    private HttpRequest.Builder jsonPost(URI uri, Map<String, String> body) {
        String json;
        try {
            json = Json.MAPPER.writeValueAsString(body);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
        return authorized(uri)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json));
    }

    private HttpRequest.Builder authorized(URI uri) {
        return HttpRequest.newBuilder(uri)
                .timeout(config.requestTimeout())
                .header("Accept", "application/json");
    }

    /**
     * Sends with the cached token. On 401 the token is renewed and the call retried once, because a
     * cached token can be revoked before its expiry.
     */
    private JsonNode sendJson(String endpoint, HttpRequest.Builder builder) {
        HttpResponse<String> response = send(endpoint, builder, tokens.token());
        if (response.statusCode() == 401) {
            tokens.invalidate();
            response = send(endpoint, builder, tokens.token());
        }
        int status = response.statusCode();
        if (status == 401 || status == 403) {
            throw new CyberArkApiException(CyberArkApiException.Kind.AUTHENTICATION, endpoint, status,
                    status == 401 ? "token not accepted" : "service user lacks permission");
        }
        if (status < 200 || status > 299) {
            throw new CyberArkApiException(CyberArkApiException.Kind.HTTP_STATUS, endpoint, status,
                    Json.snippet(response.body()));
        }
        return Json.parse(endpoint, status, response.body());
    }

    private HttpResponse<String> send(String endpoint, HttpRequest.Builder builder, String token) {
        HttpRequest request = builder.copy().setHeader("Authorization", "Bearer " + token).build();
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

    /** Escapes a value for a single-quoted Redrock string literal. */
    static String sqlLiteral(String value) {
        if (value == null) {
            throw new IllegalArgumentException("value is required");
        }
        return value.replace("'", "''");
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
