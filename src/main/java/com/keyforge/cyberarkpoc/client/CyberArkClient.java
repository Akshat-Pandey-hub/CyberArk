package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.config.ConfigException;
import com.keyforge.cyberarkpoc.config.CyberArkConfig;
import com.keyforge.cyberarkpoc.config.CyberArkConfig.RoleMembersApi;
import com.keyforge.cyberarkpoc.model.CyberArkUser;
import com.keyforge.cyberarkpoc.model.Policy;
import com.keyforge.cyberarkpoc.model.Role;
import com.keyforge.cyberarkpoc.model.RoleDetails;

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
import java.util.LinkedHashMap;
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
    public static final String SAASMANAGE_ROLE_MEMBERS_PATH = "/SaasManage/GetRoleMembers";
    public static final String POLICIES_PATH = "/policies";
    /** The SDK's default page size for policies. */
    public static final int POLICY_PAGE_LIMIT = 50;
    /** Columns of the official Role data dictionary. */
    static final String ROLE_COLUMNS = "ID, Name, RoleType, ReadOnly, Description";

    private final CyberArkConfig config;
    private final HttpClient http;
    private final TokenProvider tokens;
    private final RoleMembersApi membersApi;

    public CyberArkClient(CyberArkConfig config) {
        this(config, RoleMembersApi.ROLES);
    }

    public CyberArkClient(CyberArkConfig config, RoleMembersApi membersApi) {
        this(config, HttpClient.newBuilder()
                .connectTimeout(config.requestTimeout())
                .followRedirects(HttpClient.Redirect.NEVER)
                .build(), membersApi);
    }

    public CyberArkClient(CyberArkConfig config, HttpClient http) {
        this(config, http, RoleMembersApi.ROLES);
    }

    public CyberArkClient(CyberArkConfig config, HttpClient http, RoleMembersApi membersApi) {
        this.config = config;
        this.http = http;
        this.tokens = new TokenProvider(config, http, Clock.systemUTC());
        this.membersApi = membersApi;
    }

    public RoleMembersApi membersApi() {
        return membersApi;
    }

    /**
     * The result of a paged Redrock role search.
     *
     * @param complete  {@code false} when the paging could not show that every matching role was read
     * @param fullCount the last {@code FullCount} reported (its meaning is not documented), or {@code null}
     * @param notes     why the search is incomplete, or what could not be cross-checked
     */
    public record RoleSearch(List<Role> roles, boolean complete, int pages, Integer fullCount, List<String> notes) {
    }

    /**
     * Roles whose name matches a Redrock {@code LIKE} pattern, e.g. {@code APP-CYA-ISPSS-SCA-AWS-%-BUApprovers}, with
     * the documented paging arguments ({@code PageNumber}, {@code PageSize}, {@code Limit}, {@code Caching=-1} for
     * live data). Paging semantics are not documented, so it is conservative: {@code PageNumber} starts at 1 (as the
     * official SDK's directory search does), a page shorter than {@code pageSize} ends the search, a page that adds
     * no new role or the page limit marks the search incomplete, and a reported {@code FullCount} that differs from
     * the roles collected marks it incomplete.
     */
    public RoleSearch findRolesByNamePattern(String likePattern, int pageSize, int maxPages) {
        if (pageSize < 1 || maxPages < 1) {
            throw new IllegalArgumentException("pageSize and maxPages must be at least 1");
        }
        String script = "SELECT " + ROLE_COLUMNS + " FROM Role WHERE Name LIKE '" + sqlLiteral(likePattern)
                + "' ORDER BY ID";
        Map<String, Role> roles = new LinkedHashMap<>();
        List<String> notes = new ArrayList<>();
        boolean complete = true;
        Integer fullCount = null;
        int pages = 0;
        int duplicates = 0;
        for (int pageNumber = 1; ; pageNumber++) {
            if (pages >= maxPages) {
                complete = false;
                notes.add("stopped at the page limit (" + maxPages + " pages)");
                break;
            }
            Map<String, Object> args = new LinkedHashMap<>();
            args.put("PageNumber", pageNumber);
            args.put("PageSize", pageSize);
            args.put("Limit", pageSize);
            args.put("Caching", -1);
            IdentityResponses.RedrockPage page = IdentityResponses.page("Redrock/query (Role)", redrock(script, args));
            pages++;
            if (page.fullCount() != null) {
                fullCount = page.fullCount();
            }
            int added = 0;
            for (Role role : IdentityResponses.roles("Redrock/query (Role)", page.rows())) {
                if (roles.putIfAbsent(role.id(), role) == null) {
                    added++;
                } else {
                    duplicates++;
                }
            }
            if (page.rows().size() < pageSize) {
                break; // last page
            }
            if (added == 0) {
                complete = false;
                notes.add("paging made no progress at PageNumber " + pageNumber + " (the server returned no new roles)");
                break;
            }
        }
        if (duplicates > 0) {
            notes.add(duplicates + " duplicate role row(s) across pages were ignored");
        }
        if (fullCount == null) {
            notes.add("Redrock reported no FullCount, so the number of roles could not be cross-checked");
        } else if (fullCount != roles.size()) {
            complete = false;
            notes.add("Redrock reported FullCount " + fullCount + " but " + roles.size() + " role(s) were received");
        }
        return new RoleSearch(List.copyOf(roles.values()), complete, pages, fullCount, notes);
    }

    /** The role with this id from the Role table, or empty when the service user cannot see it. */
    public Optional<Role> findRoleById(String roleId) {
        String script = "SELECT " + ROLE_COLUMNS + " FROM Role WHERE ID='" + sqlLiteral(roleId) + "'";
        List<Role> roles = IdentityResponses.roles("Redrock/query (Role)", redrock(script, null));
        if (roles.size() > 1) {
            throw new CyberArkApiException(CyberArkApiException.Kind.INVALID_RESPONSE, "Redrock/query (Role)", 200,
                    roles.size() + " roles share the id " + roleId);
        }
        return roles.stream().findFirst();
    }

    /** GetRole. The role UUID goes in the {@code Name} query parameter (official Roles API reference). */
    public RoleDetails getRole(String roleId) {
        URI uri = URI.create(config.identityBaseUrl() + GET_ROLE_PATH + "?Name=" + urlEncode(roleId));
        JsonNode root = sendJson("Roles/GetRole", authorized(uri).POST(HttpRequest.BodyPublishers.noBody()));
        return IdentityResponses.roleDetails("Roles/GetRole", root);
    }

    /**
     * The members of a role through the configured members API (docs/API_CONTRACT.md §6). {@code ROLES}: the
     * Roles API reference passes the role UUID as the {@code name} query parameter and the SDK sends
     * {@code {"Name": ..}} in the body, so both are sent. {@code SAASMANAGE}: the data dictionary passes it as
     * {@code Name} in the query. Either documented response shape is accepted.
     */
    public IdentityResponses.MemberList getRoleMembers(String roleId) {
        String endpoint;
        HttpRequest.Builder request;
        if (membersApi == RoleMembersApi.SAASMANAGE) {
            endpoint = "SaasManage/GetRoleMembers";
            URI uri = URI.create(config.identityBaseUrl() + SAASMANAGE_ROLE_MEMBERS_PATH + "?Name=" + urlEncode(roleId));
            request = authorized(uri).POST(HttpRequest.BodyPublishers.noBody());
        } else {
            endpoint = "Roles/GetRoleMembers";
            URI uri = URI.create(config.identityBaseUrl() + GET_ROLE_MEMBERS_PATH + "?name=" + urlEncode(roleId));
            request = jsonPost(uri, Map.of("Name", roleId));
        }
        return IdentityResponses.roleMembers(endpoint, sendJson(endpoint, request));
    }

    /** The user with this id, or empty when the User table has no such row. */
    public Optional<CyberArkUser> findUserById(String userId) {
        String script = "SELECT ID, Username, DisplayName, Email, LastLogin, Status, StatusEnum FROM User WHERE ID='"
                + sqlLiteral(userId) + "'";
        List<CyberArkUser> users = IdentityResponses.users("Redrock/query (User)", redrock(script, null));
        if (users.size() > 1) {
            throw new CyberArkApiException(CyberArkApiException.Kind.INVALID_RESPONSE, "Redrock/query (User)", 200,
                    users.size() + " users share the id " + userId);
        }
        return users.stream().findFirst();
    }

    /** Every policy, following {@code nextToken} until the last page. */
    public List<Policy> listPolicies() {
        if (config.uapBaseUrl() == null) {
            throw new ConfigException(CyberArkConfig.ENV_UAP_BASE_URL + " is required for the policies");
        }
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

    /**
     * Masks the client secret and every access token this client received, then applies {@link ErrorSanitizer}.
     * Use it on any text that leaves the service (REST, database, console).
     */
    public String sanitize(String text) {
        List<String> sensitive = new ArrayList<>(tokens.issuedTokens());
        sensitive.add(config.clientSecret());
        return ErrorSanitizer.clean(text, sensitive);
    }

    /** POST {@code {"Script": ..., "args": {...}}} to Redrock and return the raw response. */
    JsonNode redrock(String script, Map<String, Object> args) {
        URI uri = URI.create(config.identityBaseUrl() + REDROCK_PATH);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("Script", script);
        if (args != null) {
            body.put("args", args); // the official example's casing (its text says "Args")
        }
        return sendJson("Redrock/query", jsonPost(uri, body));
    }

    private HttpRequest.Builder jsonPost(URI uri, Map<String, ?> body) {
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
