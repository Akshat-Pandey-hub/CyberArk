package com.keyforge.cyberarkpoc.mock;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A local stand-in for CyberArk that answers the six calls of the POC with FABRICATED data.
 *
 * <p>Response shapes follow docs/API_CONTRACT.md, including the fields marked ASSUMED there. Every
 * response carries the header {@value #MOCK_HEADER} and a top-level {@value #MOCK_FIELD} field so it
 * can never be mistaken for a tenant response.
 *
 * <p>Paths (identity calls under {@code /api}, as in the client mail):
 * <pre>
 * POST /oauth2/platformtoken
 * POST /api/Redrock/query           (Role search by Name LIKE, User lookup by ID)
 * POST /api/Roles/GetRole?Name=..
 * POST /api/Roles/GetRoleMembers?name=..   (or {"Name": ".."} in the body)
 * GET  /api/policies?limit=..&amp;nextToken=..
 * </pre>
 * Binds to 127.0.0.1 only.
 */
public final class MockCyberArkServer implements AutoCloseable {

    public static final String MOCK_HEADER = "X-Mock-Data";
    public static final String MOCK_FIELD = "_mock";
    public static final String MOCK_LABEL =
            "FABRICATED sample shaped per docs/API_CONTRACT.md - not a real CyberArk tenant response";

    /** Mock-only test credentials. They work nowhere else. */
    public static final String MOCK_CLIENT_ID = "mock-client";
    public static final String MOCK_CLIENT_SECRET = "mock-secret";

    /** Keys for {@link #fail(String, Fault)} and {@link #requestCount(String)}. */
    public static final String TOKEN = "token";
    public static final String REDROCK_ROLE = "redrock-role";
    public static final String REDROCK_USER = "redrock-user";
    public static final String REDROCK_ROLE_BY_ID = "redrock-role-by-id";
    public static final String GET_ROLE = "get-role";
    public static final String GET_ROLE_MEMBERS = "get-role-members";
    public static final String POLICIES = "policies";
    public static final String PVWA_LOGON = "pvwa-logon";
    public static final String PVWA_LOGOFF = "pvwa-logoff";
    public static final String PVWA_VERIFY = "pvwa-verify";
    public static final String PVWA_SAFES = "pvwa-safes";
    public static final String PVWA_ACCOUNTS = "pvwa-accounts";
    public static final String PVWA_SAFE_MEMBERS = "pvwa-safe-members";
    public static final String PVWA_TARGET_PLATFORMS = "pvwa-target-platforms";
    public static final String PVWA_PLATFORM_DETAILS = "pvwa-platform-details";
    public static final String PVWA_USERS = "pvwa-users";
    public static final String PVWA_USER_GROUPS = "pvwa-user-groups";
    public static final String PVWA_DISCOVERED_ACCOUNTS = "pvwa-discovered-accounts";

    /** Mock-only PVWA vault credentials. They work nowhere else. */
    public static final String MOCK_VAULT_USERNAME = "mock-vault-user";
    public static final String MOCK_VAULT_PASSWORD = "mock-vault-pass";
    /** The PVWA application path, as in {@code https://<PVWA_Server_address>/PasswordVault/...}. */
    public static final String PVWA_APP = "/PasswordVault";

    /** Injected failures for testing the client's error handling. */
    public enum Fault {
        HTTP_500, HTTP_401, HTTP_403, SUCCESS_FALSE, MALFORMED_JSON, REPEAT_NEXT_TOKEN,
        /** PVWA list endpoints: report a {@code count} one higher than the records served. */
        WRONG_COUNT,
        /** PVWA list endpoints: ignore {@code offset} and always serve the first page. */
        IGNORE_OFFSET,
        /** PVWA list endpoints: HTTP 500 whose body contains a secret, a password and a bearer token. */
        ERROR_WITH_SECRET
    }

    /** The values the {@link Fault#ERROR_WITH_SECRET} body contains; tests check that none of them leaks. */
    public static final List<String> ERROR_BODY_SECRETS =
            List.of("MOCK-ERROR-SECRET-123", "MOCK-ERROR-PASSWORD-456", "MOCK-ERROR-BEARER-789");

    private static final Pattern ROLE_QUERY =
            Pattern.compile("(?is)\\bFROM\\s+Role\\s+WHERE\\s+Name\\s+LIKE\\s+'((?:[^']|'')*)'");
    private static final Pattern ROLE_BY_ID_QUERY =
            Pattern.compile("(?is)\\bFROM\\s+Role\\s+WHERE\\s+ID\\s*=\\s*'((?:[^']|'')*)'");

    /** The two documented role-members response shapes (docs/API_CONTRACT.md §6). */
    public enum MemberShape { FLAT, NESTED }

    private volatile MemberShape memberShape = MemberShape.FLAT;

    /** Test-only: which documented shape GetRoleMembers answers with. */
    public void memberShape(MemberShape shape) {
        this.memberShape = shape;
    }

    /** The raw Redrock request bodies received (Script and args), so tests can check the paging sent. */
    private final List<String> redrockBodies = new java.util.concurrent.CopyOnWriteArrayList<>();

    public List<String> redrockBodies() {
        return redrockBodies;
    }
    private static final Pattern USER_QUERY =
            Pattern.compile("(?is)\\bFROM\\s+User\\s+WHERE\\s+ID\\s*=\\s*'((?:[^']|'')*)'");

    private final ObjectMapper mapper = new ObjectMapper();
    private final MockDataset data;
    private final HttpServer server;
    private final Set<String> issuedTokens = ConcurrentHashMap.newKeySet();
    private final Set<String> pvwaSessions = ConcurrentHashMap.newKeySet();
    private final Map<String, Fault> faults = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> counts = new ConcurrentHashMap<>();

    private MockCyberArkServer(MockDataset data, int port) throws IOException {
        this.data = data;
        this.server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 0);
        server.createContext("/", this::handle);
        server.setExecutor(Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "mock-cyberark");
            t.setDaemon(true);
            return t;
        }));
    }

    /** Starts on the given port; 0 picks a free port. */
    public static MockCyberArkServer start(MockDataset data, int port) throws IOException {
        MockCyberArkServer mock = new MockCyberArkServer(data, port);
        mock.server.start();
        return mock;
    }

    public int port() {
        return server.getAddress().getPort();
    }

    /** {@code http://127.0.0.1:<port>} */
    public String rootUrl() {
        return "http://127.0.0.1:" + port();
    }

    /** Makes every later call to {@code endpoint} fail this way, until {@link #clearFaults()}. */
    public void fail(String endpoint, Fault fault) {
        faults.put(endpoint, fault);
    }

    public void clearFaults() {
        faults.clear();
    }

    /** Invalidates all issued tokens, as if they were revoked server-side. */
    public void revokeTokens() {
        issuedTokens.clear();
    }

    public int requestCount(String endpoint) {
        AtomicInteger count = counts.get(endpoint);
        return count == null ? 0 : count.get();
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private void handle(HttpExchange exchange) throws IOException {
        try {
            route(exchange);
        } catch (IOException | RuntimeException e) {
            // e.g. a request body that is not JSON
            send(exchange, 400, error("MOCK: bad request: " + e.getClass().getSimpleName()));
        } finally {
            exchange.close();
        }
    }

    private void route(HttpExchange exchange) throws IOException {
        {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();
            if (path.regionMatches(true, 0, PVWA_APP + "/", 0, PVWA_APP.length() + 1)) {
                pvwa(exchange, path.substring(PVWA_APP.length()), method);
                return;
            }
            switch (path) {
                case "/oauth2/platformtoken" -> requirePost(exchange, method, this::token);
                case "/api/Redrock/query" -> requirePost(exchange, method, this::redrock);
                case "/api/Roles/GetRole" -> requirePost(exchange, method, this::getRole);
                case "/api/Roles/GetRoleMembers" -> requirePost(exchange, method, this::getRoleMembers);
                case "/api/SaasManage/GetRoleMembers" -> requirePost(exchange, method, this::getRoleMembers);
                case "/api/policies" -> {
                    if (method.equals("GET")) {
                        policies(exchange);
                    } else {
                        send(exchange, 405, error("method not allowed"));
                    }
                }
                default -> send(exchange, 404, error("MOCK: unknown path " + path));
            }
        }
    }

    private interface Handler {
        void handle(HttpExchange exchange) throws IOException;
    }

    // ---- PVWA (PAM Self-Hosted) ------------------------------------------------------------

    private static final Pattern PVWA_LOGON_PATH =
            Pattern.compile("(?i)/API/auth/(Cyberark|LDAP|RADIUS|Windows)/Logon/?");

    /** PVWA paths are matched case-insensitively, with or without the documented trailing slash. */
    private void pvwa(HttpExchange exchange, String sub, String method) throws IOException {
        String path = sub.endsWith("/") ? sub.substring(0, sub.length() - 1) : sub;
        if (PVWA_LOGON_PATH.matcher(sub).matches()) {
            requirePost(exchange, method, this::pvwaLogon);
        } else if (path.equalsIgnoreCase("/API/Auth/Logoff")) {
            requirePost(exchange, method, this::pvwaLogoff);
        } else if (path.equalsIgnoreCase("/WebServices/PIMServices.svc/Verify")) {
            requireGet(exchange, method, this::pvwaVerify);
        } else if (path.equalsIgnoreCase("/API/Safes")) {
            requireGet(exchange, method, ex -> pvwaList(ex, PVWA_SAFES, data.safes, 25, "api/safes"));
        } else if (path.equalsIgnoreCase("/API/Accounts")) {
            requireGet(exchange, method, ex -> pvwaList(ex, PVWA_ACCOUNTS, data.accounts, 50, "api/accounts"));
        } else if (path.equalsIgnoreCase("/API/DiscoveredAccounts")) {
            requireGet(exchange, method, ex -> pvwaList(ex, PVWA_DISCOVERED_ACCOUNTS, data.discoveredAccounts, 100,
                    "api/DiscoveredAccounts"));
        } else if (path.equalsIgnoreCase("/API/UserGroups")) {
            requireGet(exchange, method, this::pvwaUserGroups);
        } else if (path.equalsIgnoreCase("/API/Users")) {
            requireGet(exchange, method, this::pvwaUsers);
        } else if (path.equalsIgnoreCase("/API/platforms/targets")) {
            requireGet(exchange, method, this::pvwaTargetPlatforms);
        } else if (PLATFORM_DETAILS_PATH.matcher(path).matches()) {
            String platformId = PLATFORM_DETAILS_PATH.matcher(path).replaceFirst("$1");
            requireGet(exchange, method, ex -> pvwaPlatformDetails(ex, platformId));
        } else if (SAFE_MEMBERS_PATH.matcher(path).matches()) {
            String safeUrlId = SAFE_MEMBERS_PATH.matcher(path).replaceFirst("$1");
            requireGet(exchange, method, ex -> pvwaSafeMembers(ex, safeUrlId));
        } else {
            send(exchange, 404, error("MOCK: unknown PVWA path " + sub));
        }
    }

    private static final Pattern SAFE_MEMBERS_PATH = Pattern.compile("(?i)/API/Safes/([^/]+)/Members");

    /** Safes whose members answer 403, to test a missing View Safe Members permission on one Safe. */
    private final Set<String> forbiddenMemberSafes = ConcurrentHashMap.newKeySet();

    public void forbidSafeMembers(String safeUrlId) {
        forbiddenMemberSafes.add(safeUrlId);
    }

    /** Official "Get all Safe members": {"value": [...], "count": n}; unknown Safe → 404. */
    private void pvwaSafeMembers(HttpExchange exchange, String safeUrlId) throws IOException {
        if (forbiddenMemberSafes.contains(safeUrlId)) {
            count(PVWA_SAFE_MEMBERS);
            if (pvwaAuthorized(exchange)) {
                send(exchange, 403, error("MOCK: the user lacks View Safe Members in " + safeUrlId));
            }
            return;
        }
        List<ObjectNode> list = data.safeMembers.get(safeUrlId);
        if (list == null && data.safes.stream().noneMatch(s -> s.path("safeUrlId").asText().equals(safeUrlId))) {
            count(PVWA_SAFE_MEMBERS);
            send(exchange, 404, error("MOCK: unknown Safe " + safeUrlId));
            return;
        }
        pvwaList(exchange, PVWA_SAFE_MEMBERS, list == null ? List.of() : list, 25,
                "api/safes/" + safeUrlId + "/members");
    }

    /** Official "Get target platforms": {"Platforms": [...], "Total": n}, no paging. */
    private void pvwaTargetPlatforms(HttpExchange exchange) throws IOException {
        count(PVWA_TARGET_PLATFORMS);
        if (!pvwaAuthorized(exchange)) {
            return;
        }
        Fault fault = faults.get(PVWA_TARGET_PLATFORMS);
        if (fault != null && fault != Fault.WRONG_COUNT && applyFault(exchange, PVWA_TARGET_PLATFORMS)) {
            return;
        }
        ObjectNode body = labelled();
        ArrayNode platforms = body.putArray("Platforms");
        data.targetPlatforms.forEach(platforms::add);
        body.put("Total", data.targetPlatforms.size() + (fault == Fault.WRONG_COUNT ? 1 : 0));
        send(exchange, 200, body);
    }

    /** The raw query strings received on Get users, so tests can check what was sent. */
    private final List<String> usersQueries = new java.util.concurrent.CopyOnWriteArrayList<>();

    public List<String> usersQueries() {
        return usersQueries;
    }

    /**
     * Official "Get users": {@code pageOffset} / {@code pageSize} paging (no pageSize = all users), result
     * {@code {"Users": [...], "Total": n}} with Total = all users; the ExtendedDetails-only fields are added when
     * {@code ExtendedDetails=true}. Organization and department go into personalDetails, as documented.
     */
    private void pvwaUsers(HttpExchange exchange) throws IOException {
        count(PVWA_USERS);
        usersQueries.add(String.valueOf(exchange.getRequestURI().getRawQuery()));
        if (!pvwaAuthorized(exchange)) {
            return;
        }
        Fault fault = faults.get(PVWA_USERS);
        if (fault != null && fault != Fault.WRONG_COUNT && fault != Fault.IGNORE_OFFSET
                && applyFault(exchange, PVWA_USERS)) {
            return;
        }
        Map<String, String> query = parseForm(exchange.getRequestURI().getRawQuery());
        boolean extended = "true".equalsIgnoreCase(query.get("ExtendedDetails"));
        List<ObjectNode> all = data.vaultUsers;
        int offset = fault == Fault.IGNORE_OFFSET ? 0 : intParam(query.get("pageOffset"), 0);
        int size = intParam(query.get("pageSize"), 0);
        int end = size == 0 ? all.size() : Math.min(offset + size, all.size());
        ObjectNode body = labelled();
        ArrayNode users = body.putArray("Users");
        for (ObjectNode entry : all.subList(Math.min(offset, end), end)) {
            ObjectNode user = entry.get("base").deepCopy();
            if (extended) {
                ObjectNode ext = (ObjectNode) entry.get("extended");
                ext.fields().forEachRemaining(f -> {
                    if (f.getKey().equals("organization") || f.getKey().equals("department")) {
                        ((ObjectNode) user.get("personalDetails")).set(f.getKey(), f.getValue());
                    } else {
                        user.set(f.getKey(), f.getValue());
                    }
                });
            }
            users.add(user);
        }
        body.put("Total", all.size() + (fault == Fault.WRONG_COUNT ? 1 : 0));
        send(exchange, 200, body);
    }

    /** The raw query strings received on Get groups, so tests can check what was sent. */
    private final List<String> userGroupsQueries = new java.util.concurrent.CopyOnWriteArrayList<>();

    public List<String> userGroupsQueries() {
        return userGroupsQueries;
    }

    /** Official "Get groups": offset/limit, {"value", "count", "nextLink"}; members only with includeMembers=true. */
    private void pvwaUserGroups(HttpExchange exchange) throws IOException {
        userGroupsQueries.add(String.valueOf(exchange.getRequestURI().getRawQuery()));
        boolean members = "true".equalsIgnoreCase(parseForm(exchange.getRequestURI().getRawQuery()).get("includeMembers"));
        List<ObjectNode> groups = data.userGroups.stream().map(g -> {
            ObjectNode copy = g.deepCopy();
            if (!members) {
                copy.remove("members");
            }
            return copy;
        }).toList();
        pvwaList(exchange, PVWA_USER_GROUPS, groups, 25, "api/usergroups");
    }

    private static final Pattern PLATFORM_DETAILS_PATH = Pattern.compile("(?i)/API/Platforms/([^/]+)");

    /** Platforms whose details answer 403. */
    private final Set<String> forbiddenPlatformDetails = ConcurrentHashMap.newKeySet();

    public void forbidPlatformDetails(String platformId) {
        forbiddenPlatformDetails.add(platformId);
    }

    /**
     * Official "Get platform details": {"PlatformID", "Properties", "Active"}; unknown platform → 404. The whole body is
     * the record, so it carries no {@code _mock} field (the {@code X-Mock-Data} header still marks it as fabricated).
     */
    private void pvwaPlatformDetails(HttpExchange exchange, String platformId) throws IOException {
        count(PVWA_PLATFORM_DETAILS);
        if (!pvwaAuthorized(exchange) || applyFault(exchange, PVWA_PLATFORM_DETAILS)) {
            return;
        }
        if (forbiddenPlatformDetails.contains(platformId)) {
            send(exchange, 403, error("MOCK: the user may not read platform " + platformId));
            return;
        }
        ObjectNode details = data.platformDetails.get(platformId);
        if (details == null) {
            send(exchange, 404, error("MOCK: unknown platform " + platformId));
            return;
        }
        send(exchange, 200, details);
    }

    private void requireGet(HttpExchange exchange, String method, Handler handler) throws IOException {
        if (!method.equals("GET")) {
            send(exchange, 405, error("method not allowed"));
            return;
        }
        handler.handle(exchange);
    }

    /** Official Logon: JSON body {"username", "password"}; the result is the session token as a JSON string. */
    private void pvwaLogon(HttpExchange exchange) throws IOException {
        count(PVWA_LOGON);
        if (applyFault(exchange, PVWA_LOGON)) {
            return;
        }
        var body = mapper.readTree(readBody(exchange));
        if (!MOCK_VAULT_USERNAME.equals(body.path("username").asText(null))
                || !MOCK_VAULT_PASSWORD.equals(body.path("password").asText(null))) {
            send(exchange, 401, error("MOCK: authentication failure"));
            return;
        }
        String token = "mock-pvwa-session-" + UUID.randomUUID();
        pvwaSessions.add(token);
        sendRaw(exchange, 200, mapper.writeValueAsString(token));
    }

    private void pvwaLogoff(HttpExchange exchange) throws IOException {
        count(PVWA_LOGOFF);
        String token = exchange.getRequestHeaders().getFirst("Authorization");
        if (token == null || !pvwaSessions.remove(token)) {
            send(exchange, 401, error("MOCK: unknown session"));
            return;
        }
        send(exchange, 200, mapper.createObjectNode());
    }

    /** Official Verify result fields: ServerName, ServerID, ApplicationName, AuthenticationMethods. */
    private void pvwaVerify(HttpExchange exchange) throws IOException {
        count(PVWA_VERIFY);
        if (!pvwaAuthorized(exchange) || applyFault(exchange, PVWA_VERIFY)) {
            return;
        }
        ObjectNode body = labelled();
        body.put("ServerName", "MOCK Vault");
        body.put("ServerID", "mock-vault-0001");
        body.put("ApplicationName", "PasswordVault");
        ArrayNode methods = body.putArray("AuthenticationMethods");
        for (String id : List.of("cyberark", "ldap", "radius", "windows")) {
            ObjectNode m = methods.addObject();
            m.put("Id", id);
            m.put("Enabled", !id.equals("windows"));
        }
        send(exchange, 200, body);
    }

    /**
     * A PVWA list endpoint with the documented offset/limit paging and {@code {"value", "count", "nextLink"}}
     * result ({@code count} = total; {@code nextLink} only when more records follow).
     */
    private void pvwaList(HttpExchange exchange, String key, List<ObjectNode> all, int defaultLimit, String linkBase)
            throws IOException {
        count(key);
        if (!pvwaAuthorized(exchange)) {
            return;
        }
        Fault fault = faults.get(key);
        if (fault == Fault.ERROR_WITH_SECRET) {
            ObjectNode error = labelled();
            error.put("ErrorCode", "MOCK500");
            error.put("ErrorMessage", "MOCK failure; password=" + ERROR_BODY_SECRETS.get(1)
                    + "; Authorization: Bearer " + ERROR_BODY_SECRETS.get(2));
            error.put("secret", ERROR_BODY_SECRETS.get(0));
            send(exchange, 500, error);
            return;
        }
        if (fault != null && fault != Fault.WRONG_COUNT && fault != Fault.IGNORE_OFFSET && applyFault(exchange, key)) {
            return;
        }
        Map<String, String> query = parseForm(exchange.getRequestURI().getRawQuery());
        int offset = fault == Fault.IGNORE_OFFSET ? 0 : intParam(query.get("offset"), 0);
        int limit = intParam(query.get("limit"), defaultLimit);
        int end = Math.min(offset + limit, all.size());
        ObjectNode body = labelled();
        ArrayNode value = body.putArray("value");
        for (ObjectNode item : all.subList(Math.min(offset, end), end)) {
            value.add(item);
        }
        body.put("count", all.size() + (fault == Fault.WRONG_COUNT ? 1 : 0));
        if (end < all.size()) {
            body.put("nextLink", linkBase + "?offset=" + end + "&limit=" + limit + "&useCache=False");
        }
        send(exchange, 200, body);
    }

    private static int intParam(String value, int fallback) {
        if (value == null || !value.matches("\\d+")) {
            return fallback;
        }
        return Integer.parseInt(value);
    }

    /** PVWA sends the session token itself in the Authorization header (no "Bearer"). */
    private boolean pvwaAuthorized(HttpExchange exchange) throws IOException {
        String token = exchange.getRequestHeaders().getFirst("Authorization");
        if (token == null || !pvwaSessions.contains(token)) {
            send(exchange, 401, error("MOCK: missing or unknown PVWA session token"));
            return false;
        }
        return true;
    }

    /** Ends every open PVWA session, as if they expired. */
    public void expirePvwaSessions() {
        pvwaSessions.clear();
    }

    /** Number of PVWA sessions still open (tests check that every run logs off). */
    public int openPvwaSessions() {
        return pvwaSessions.size();
    }

    private void requirePost(HttpExchange exchange, String method, Handler handler) throws IOException {
        if (!method.equals("POST")) {
            send(exchange, 405, error("method not allowed"));
            return;
        }
        handler.handle(exchange);
    }

    // ---- token ---------------------------------------------------------------------------

    private void token(HttpExchange exchange) throws IOException {
        count(TOKEN);
        if (applyFault(exchange, TOKEN)) {
            return;
        }
        Map<String, String> form = parseForm(readBody(exchange));
        if (!"client_credentials".equals(form.get("grant_type"))
                || !MOCK_CLIENT_ID.equals(form.get("client_id"))
                || !MOCK_CLIENT_SECRET.equals(form.get("client_secret"))) {
            send(exchange, 401, error("invalid_client"));
            return;
        }
        String token = "mock-token-" + UUID.randomUUID();
        issuedTokens.add(token);
        ObjectNode body = labelled();
        body.put("access_token", token);
        body.put("token_type", "Bearer");
        body.put("expires_in", 3600);
        send(exchange, 200, body);
    }

    // ---- identity ------------------------------------------------------------------------

    private void redrock(HttpExchange exchange) throws IOException {
        String raw = readBody(exchange);
        redrockBodies.add(raw);
        var request = mapper.readTree(raw);
        String script = request.path("Script").asText("");
        var args = request.has("args") ? request.get("args") : request.path("Args");
        Matcher role = ROLE_QUERY.matcher(script);
        Matcher roleById = ROLE_BY_ID_QUERY.matcher(script);
        Matcher user = USER_QUERY.matcher(script);
        if (role.find()) {
            redrockRoles(exchange, unquote(role.group(1)), args.path("PageNumber").asInt(0),
                    args.path("PageSize").asInt(0));
        } else if (roleById.find()) {
            redrockRoleById(exchange, unquote(roleById.group(1)));
        } else if (user.find()) {
            redrockUser(exchange, unquote(user.group(1)));
        } else {
            count("redrock-other");
            if (authorized(exchange)) {
                send(exchange, 200, failure("MOCK: this Redrock query is not supported by the mock"));
            }
        }
    }

    /**
     * Role search with the documented paging arguments: 1-based {@code PageNumber} and {@code PageSize} (no args =
     * everything), {@code Count} = rows on this page, {@code FullCount} = all matching roles. Faults: WRONG_COUNT
     * reports a FullCount one higher; IGNORE_OFFSET always serves the first page.
     */
    private void redrockRoles(HttpExchange exchange, String likePattern, int pageNumber, int pageSize)
            throws IOException {
        count(REDROCK_ROLE);
        Fault fault = faults.get(REDROCK_ROLE);
        if (!authorized(exchange)
                || (fault != Fault.WRONG_COUNT && fault != Fault.IGNORE_OFFSET && applyFault(exchange, REDROCK_ROLE))) {
            return;
        }
        Pattern regex = likeToRegex(likePattern);
        List<ObjectNode> matching = new java.util.ArrayList<>();
        for (MockDataset.RoleRow row : data.roles.values()) {
            if (regex.matcher(row.name()).matches()) {
                matching.add(roleRow(row));
            }
        }
        matching.sort(java.util.Comparator.comparing(n -> n.get("ID").asText()));
        int from = 0;
        int to = matching.size();
        if (pageSize > 0) {
            int page = fault == Fault.IGNORE_OFFSET ? 1 : Math.max(pageNumber, 1);
            from = Math.min((page - 1) * pageSize, matching.size());
            to = Math.min(from + pageSize, matching.size());
        }
        ArrayNode results = mapper.createArrayNode();
        matching.subList(from, to).forEach(r -> results.addObject().set("Row", r));
        ObjectNode body = success(results);
        ((ObjectNode) body.get("Result")).put("FullCount", matching.size() + (fault == Fault.WRONG_COUNT ? 1 : 0));
        send(exchange, 200, body);
    }

    private void redrockRoleById(HttpExchange exchange, String roleId) throws IOException {
        count(REDROCK_ROLE_BY_ID);
        if (!authorized(exchange) || applyFault(exchange, REDROCK_ROLE_BY_ID)) {
            return;
        }
        ArrayNode results = mapper.createArrayNode();
        MockDataset.RoleRow row = data.roles.get(roleId);
        if (row != null && !data.hiddenRoles.contains(roleId)) {
            results.addObject().set("Row", roleRow(row));
        }
        send(exchange, 200, success(results));
    }

    /** A Role table row with the documented columns. */
    private ObjectNode roleRow(MockDataset.RoleRow row) {
        ObjectNode r = mapper.createObjectNode();
        r.put("ID", row.id());
        r.put("Name", row.name());
        r.put("RoleType", data.roleTypes.getOrDefault(row.id(), "PrincipalList"));
        r.put("ReadOnly", false);
        r.put("Description", row.description());
        return r;
    }

    private void redrockUser(HttpExchange exchange, String userId) throws IOException {
        count(REDROCK_USER);
        if (!authorized(exchange) || applyFault(exchange, REDROCK_USER)) {
            return;
        }
        ArrayNode results = mapper.createArrayNode();
        MockDataset.UserRow user = data.users.get(userId);
        if (user != null) {
            ObjectNode r = mapper.createObjectNode();
            r.put("ID", user.id());
            r.put("Username", user.username());
            r.put("DisplayName", user.displayName());
            r.put("Email", user.email());
            r.put("LastLogin", user.lastLogin());
            r.put("Status", user.status());
            r.put("StatusEnum", user.statusEnum());
            results.addObject().set("Row", r);
        }
        send(exchange, 200, success(results));
    }

    private void getRole(HttpExchange exchange) throws IOException {
        count(GET_ROLE);
        if (!authorized(exchange) || applyFault(exchange, GET_ROLE)) {
            return;
        }
        String roleId = parseForm(exchange.getRequestURI().getRawQuery()).get("Name");
        MockDataset.RoleRow row = roleId == null ? null : data.roles.get(roleId);
        if (row == null) {
            send(exchange, 200, failure("MOCK: role not found"));
            return;
        }
        // Fields per the official Roles API reference.
        ObjectNode body = labelled();
        body.put("success", true);
        ObjectNode result = body.putObject("Result");
        result.put("Uuid", row.id());
        result.put("Name", row.name());
        result.put("Description", row.description());
        result.put("RoleType", "PrincipalList");
        result.put("ReadOnly", false);
        ArrayNode principals = result.putArray("Principals");
        data.members.getOrDefault(row.id(), List.of()).forEach(m -> principals.add(m.guid()));
        body.putNull("Message");
        send(exchange, 200, body);
    }

    /**
     * Role members in the selected documented shape ({@link #memberShape}): FLAT = the Redrock envelope with one
     * {@code Row} object per member; NESTED = the Roles API reference example, {@code success} inside {@code Result}
     * and one {@code Row} array. Both report {@code FullCount}; fault WRONG_COUNT reports one more than listed.
     */
    private void getRoleMembers(HttpExchange exchange) throws IOException {
        count(GET_ROLE_MEMBERS);
        Fault fault = faults.get(GET_ROLE_MEMBERS);
        if (!authorized(exchange) || (fault != Fault.WRONG_COUNT && applyFault(exchange, GET_ROLE_MEMBERS))) {
            return;
        }
        // Roles API reference: 'name' query parameter; SDK: {"Name": ..} body; data dictionary (SaasManage): 'Name'.
        Map<String, String> query = parseForm(exchange.getRequestURI().getRawQuery());
        String roleId = query.getOrDefault("name", query.get("Name"));
        String body = readBody(exchange);
        if (roleId == null && !body.isBlank()) {
            roleId = mapper.readTree(body).path("Name").asText(null);
        }
        List<MockDataset.MemberRow> members = roleId == null ? null : data.members.get(roleId);
        if (members == null) {
            send(exchange, 200, failure("MOCK: role not found"));
            return;
        }
        int fullCount = members.size() + (fault == Fault.WRONG_COUNT ? 1 : 0);
        if (memberShape == MemberShape.NESTED) {
            ObjectNode root = labelled();
            ObjectNode outer = root.putObject("Result");
            ObjectNode inner = outer.putObject("Result");
            ArrayNode rows = inner.putArray("Results").addObject().putArray("Row");
            for (MockDataset.MemberRow member : members) {
                ObjectNode r = rows.addObject();
                r.put("IsEffective", true);
                r.put("OrgPath", "");
                r.put("OrgId", "");
                r.put("Guid", member.guid());
                r.put("Type", member.type());
                r.put("Name", member.name());
            }
            inner.put("count", members.size());
            inner.put("FullCount", fullCount);
            outer.put("success", true);
            outer.put("IsSoftError", false);
            outer.putNull("Message");
            send(exchange, 200, root);
            return;
        }
        ArrayNode results = mapper.createArrayNode();
        for (MockDataset.MemberRow member : members) {
            ObjectNode r = mapper.createObjectNode();
            r.put("Guid", member.guid());
            r.put("Name", member.name());
            r.put("Type", member.type());
            results.addObject().set("Row", r);
        }
        ObjectNode flat = success(results);
        ((ObjectNode) flat.get("Result")).put("FullCount", fullCount);
        send(exchange, 200, flat);
    }

    // ---- policies ------------------------------------------------------------------------

    private void policies(HttpExchange exchange) throws IOException {
        count(POLICIES);
        if (!authorized(exchange)) {
            return;
        }
        Fault fault = faults.get(POLICIES);
        if (fault != null && fault != Fault.REPEAT_NEXT_TOKEN && applyFault(exchange, POLICIES)) {
            return;
        }
        Map<String, String> query = parseForm(exchange.getRequestURI().getRawQuery());
        int offset = 0;
        String nextToken = query.get("nextToken");
        if (nextToken != null) {
            try {
                offset = Integer.parseInt(new String(Base64.getDecoder().decode(nextToken), StandardCharsets.UTF_8)
                        .replace("offset:", ""));
            } catch (IllegalArgumentException e) {
                send(exchange, 400, error("MOCK: bad nextToken"));
                return;
            }
        }
        int pageSize = data.policyPageSize;
        String limit = query.get("limit");
        if (limit != null && limit.matches("\\d+") && Integer.parseInt(limit) > 0) {
            pageSize = Math.min(pageSize, Integer.parseInt(limit));
        }
        int end = Math.min(offset + pageSize, data.policies.size());
        ObjectNode body = labelled();
        ArrayNode results = body.putArray("results");
        for (MockDataset.PolicyRow row : data.policies.subList(Math.min(offset, end), end)) {
            results.add(policyJson(row));
        }
        if (fault == Fault.REPEAT_NEXT_TOKEN) {
            body.put("nextToken", encodeOffset(0));
        } else if (end < data.policies.size()) {
            body.put("nextToken", encodeOffset(end));
        }
        body.put("total", data.policies.size());
        send(exchange, 200, body);
    }

    private ObjectNode policyJson(MockDataset.PolicyRow row) {
        ObjectNode policy = mapper.createObjectNode();
        ObjectNode metadata = policy.putObject("metadata");
        metadata.put("policyId", row.policyId());
        metadata.put("name", row.name());
        metadata.put("description", "MOCK policy");
        ObjectNode status = metadata.putObject("status");
        status.put("status", row.status());
        status.put("statusCode", row.statusCode());
        status.put("statusDescription", row.statusDescription());
        status.put("link", (String) null);
        ObjectNode timeFrame = metadata.putObject("timeFrame");
        timeFrame.putNull("fromTime");
        timeFrame.putNull("toTime");
        ObjectNode entitlement = metadata.putObject("policyEntitlement");
        entitlement.put("targetCategory", row.targetCategory());
        entitlement.put("locationType", row.locationType());
        entitlement.put("policyType", "Recurring");
        ObjectNode createdBy = metadata.putObject("createdBy");
        createdBy.put("user", "mock.admin@example.test");
        createdBy.put("time", "2026-09-01T10:00:00");
        ObjectNode updatedOn = metadata.putObject("updatedOn");
        updatedOn.put("user", "mock.admin@example.test");
        updatedOn.put("time", "2026-10-10T08:30:00");
        metadata.putArray("policyTags");
        metadata.put("timeZone", "GMT");
        policy.putArray("principals");
        policy.put("delegationClassification", "Unrestricted");
        return policy;
    }

    private static String encodeOffset(int offset) {
        return Base64.getEncoder().encodeToString(("offset:" + offset).getBytes(StandardCharsets.UTF_8));
    }

    // ---- helpers -------------------------------------------------------------------------

    private boolean authorized(HttpExchange exchange) throws IOException {
        String header = exchange.getRequestHeaders().getFirst("Authorization");
        if (header == null || !header.startsWith("Bearer ") || !issuedTokens.contains(header.substring(7))) {
            send(exchange, 401, error("MOCK: missing or unknown bearer token"));
            return false;
        }
        return true;
    }

    /** Sends the configured fault for {@code endpoint}, if any. Returns true when it did. */
    private boolean applyFault(HttpExchange exchange, String endpoint) throws IOException {
        Fault fault = faults.get(endpoint);
        if (fault == null) {
            return false;
        }
        switch (fault) {
            case HTTP_500 -> send(exchange, 500, error("MOCK: injected internal error"));
            case HTTP_401 -> send(exchange, 401, error("MOCK: injected unauthorized"));
            case HTTP_403 -> send(exchange, 403, error("MOCK: injected forbidden"));
            case SUCCESS_FALSE -> send(exchange, 200, failure("MOCK: injected success=false"));
            case MALFORMED_JSON -> sendRaw(exchange, 200, "{ this is not json");
            case REPEAT_NEXT_TOKEN -> {
                return false;
            }
        }
        return true;
    }

    private void count(String endpoint) {
        counts.computeIfAbsent(endpoint, k -> new AtomicInteger()).incrementAndGet();
    }

    private ObjectNode labelled() {
        ObjectNode node = mapper.createObjectNode();
        node.put(MOCK_FIELD, MOCK_LABEL);
        return node;
    }

    private ObjectNode success(ArrayNode results) {
        ObjectNode body = labelled();
        body.put("success", true);
        ObjectNode result = body.putObject("Result");
        result.put("Count", results.size());
        result.set("Results", results);
        body.putNull("Message");
        return body;
    }

    private ObjectNode failure(String message) {
        ObjectNode body = labelled();
        body.put("success", false);
        body.putNull("Result");
        body.put("Message", message);
        return body;
    }

    private ObjectNode error(String message) {
        ObjectNode body = labelled();
        body.put("error", message);
        return body;
    }

    private void send(HttpExchange exchange, int status, ObjectNode body) throws IOException {
        sendRaw(exchange, status, mapper.writerWithDefaultPrettyPrinter().writeValueAsString(body));
    }

    private void sendRaw(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.getResponseHeaders().set(MOCK_HEADER, "FABRICATED - not a CyberArk tenant response");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static String readBody(HttpExchange exchange) throws IOException {
        try (InputStream in = exchange.getRequestBody()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static Map<String, String> parseForm(String raw) {
        Map<String, String> values = new HashMap<>();
        if (raw == null || raw.isBlank()) {
            return values;
        }
        for (String pair : raw.split("&")) {
            int eq = pair.indexOf('=');
            String key = URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), StandardCharsets.UTF_8);
            String value = eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            values.put(key, value);
        }
        return values;
    }

    private static String unquote(String literal) {
        return literal.replace("''", "'");
    }

    /** SQL LIKE: {@code %} any run, {@code _} one character, case-insensitive. */
    static Pattern likeToRegex(String like) {
        StringBuilder regex = new StringBuilder();
        for (char c : like.toCharArray()) {
            switch (c) {
                case '%' -> regex.append(".*");
                case '_' -> regex.append('.');
                default -> regex.append(Pattern.quote(String.valueOf(c)));
            }
        }
        return Pattern.compile(regex.toString(), Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    }

    /** For log output. */
    public static String describeEndpoints(String root) {
        return String.join(System.lineSeparator(),
                "  POST " + root + "/oauth2/platformtoken",
                "  POST " + root + "/api/Redrock/query",
                "  POST " + root + "/api/Roles/GetRole?Name=<roleId>",
                "  POST " + root + "/api/Roles/GetRoleMembers?name=<roleId>",
                "  GET  " + root + "/api/policies?limit=50&nextToken=<token>",
                "  POST " + root + PVWA_APP + "/API/auth/{Cyberark|LDAP|RADIUS|Windows}/Logon/",
                "  POST " + root + PVWA_APP + "/API/Auth/Logoff/",
                "  GET  " + root + PVWA_APP + "/WebServices/PIMServices.svc/Verify/",
                "  GET  " + root + PVWA_APP + "/API/Safes/?offset=&limit=",
                "  GET  " + root + PVWA_APP + "/API/Accounts?offset=&limit=",
                "  GET  " + root + PVWA_APP + "/API/Safes/{SafeUrlId}/Members/?offset=&limit=",
                "  GET  " + root + PVWA_APP + "/API/platforms/targets/",
                "  GET  " + root + PVWA_APP + "/API/Platforms/{PlatformID}/",
                "  GET  " + root + PVWA_APP + "/API/Users/?ExtendedDetails=true&pageOffset=&pageSize=",
                "  GET  " + root + PVWA_APP + "/API/UserGroups/?includeMembers=true&offset=&limit=",
                "  GET  " + root + PVWA_APP + "/API/DiscoveredAccounts/?offset=&limit=");
    }
}
