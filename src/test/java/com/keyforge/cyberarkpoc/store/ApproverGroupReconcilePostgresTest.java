package com.keyforge.cyberarkpoc.store;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.keyforge.cyberarkpoc.StubHttpServer;
import com.keyforge.cyberarkpoc.check.ApproverGroupRun;
import com.keyforge.cyberarkpoc.client.CyberArkClient;
import com.keyforge.cyberarkpoc.config.CyberArkConfig;
import com.sun.net.httpserver.HttpExchange;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Use Case 1 rows no longer returned ({@code missing_since}), the run lock and the column upgrade, against a REAL
 * PostgreSQL (throwaway schema) and a small programmable stub of the Identity APIs (made-up data). Runs only when the
 * {@code CYBERARK_IT_PG_*} variables point at a test database; otherwise every test is skipped.
 */
class ApproverGroupReconcilePostgresTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String PATTERN = "APP-%";

    /** How a list answers: as documented, or with one of the signals that make it unprovable. */
    enum Mode { OK, NO_FULLCOUNT, WRONG_FULLCOUNT, SOFT_ERROR, DUPLICATE, FAIL }

    /** A programmable Identity tenant: roles found by the search, member lists per role, every user Active. */
    static final class Tenant implements AutoCloseable {
        final Map<String, String> roles = new LinkedHashMap<>(); // id -> RoleType, in search order
        final Map<String, List<String[]>> members = new ConcurrentHashMap<>(); // role id -> {Guid, Type}
        final Map<String, Mode> memberMode = new ConcurrentHashMap<>();
        volatile Mode searchMode = Mode.OK;
        volatile boolean duplicateRole;
        volatile long searchDelayMs;
        final AtomicInteger calls = new AtomicInteger();
        final StubHttpServer stub;

        Tenant() {
            stub = new StubHttpServer()
                    .reply("/oauth2/platformtoken", 200, "{\"access_token\":\"tok-uc1\",\"expires_in\":900}")
                    .handle("/api/Redrock/query", this::redrock)
                    .handle("/api/Roles/GetRole", ex -> send(ex, 200, "{\"success\":true,\"Result\":{\"Uuid\":\""
                            + param(ex, "Name") + "\",\"Principals\":[]}}"))
                    .handle("/api/Roles/GetRoleMembers", this::members);
        }

        Tenant role(String id, String... memberSpecs) {
            roles.put(id, "PrincipalList");
            List<String[]> list = new ArrayList<>();
            for (String spec : memberSpecs) {
                list.add(spec.startsWith("role:") ? new String[] {spec.substring(5), "Role"} : new String[] {spec, "User"});
            }
            members.put(id, list);
            return this;
        }

        /** A role that is only reached as a nested member (not found by the search). */
        Tenant nested(String id, String... userIds) {
            role(id, userIds);
            roles.remove(id);
            nestedRoles.add(id);
            return this;
        }

        final List<String> nestedRoles = new ArrayList<>();

        CyberArkClient client() {
            return new CyberArkClient(new CyberArkConfig(URI.create(stub.rootUrl() + "/api"),
                    URI.create(stub.rootUrl() + "/oauth2/platformtoken"), "client", "uc1-secret", Duration.ofSeconds(5),
                    CyberArkConfig.AuthMethod.PLATFORM, null, null, null));
        }

        private void redrock(HttpExchange ex) throws IOException {
            calls.incrementAndGet();
            JsonNode body = MAPPER.readTree((byte[]) ex.getAttribute(StubHttpServer.REQUEST_BODY));
            String script = body.path("Script").asText();
            Matcher id = Pattern.compile("ID\\s*=\\s*'([^']*)'").matcher(script);
            if (script.contains("FROM Role WHERE Name LIKE")) {
                if (searchDelayMs > 0) {
                    try {
                        Thread.sleep(searchDelayMs);
                    } catch (InterruptedException e) {
                        return;
                    }
                }
                List<String> ids = new ArrayList<>(roles.keySet());
                int size = body.path("args").path("PageSize").asInt(1000);
                int page = body.path("args").path("PageNumber").asInt(1);
                int from = Math.min((page - 1) * size, ids.size());
                List<String> slice = new ArrayList<>(ids.subList(from, Math.min(from + size, ids.size())));
                if (duplicateRole && !slice.isEmpty()) {
                    slice.add(slice.get(0));
                }
                ArrayNode rows = MAPPER.createArrayNode();
                slice.forEach(r -> rows.addObject().set("Row", roleRow(r)));
                send(ex, 200, redrockBody(rows, searchMode == Mode.NO_FULLCOUNT ? null
                        : ids.size() + (searchMode == Mode.WRONG_FULLCOUNT ? 1 : 0)));
            } else if (script.contains("FROM Role WHERE ID") && id.find()) {
                ArrayNode rows = MAPPER.createArrayNode();
                if (roles.containsKey(id.group(1)) || nestedRoles.contains(id.group(1))) {
                    rows.addObject().set("Row", roleRow(id.group(1)));
                }
                send(ex, 200, redrockBody(rows, rows.size()));
            } else if (script.contains("FROM User") && id.find()) {
                ArrayNode rows = MAPPER.createArrayNode();
                ObjectNode u = rows.addObject().putObject("Row");
                u.put("ID", id.group(1)).put("Username", id.group(1) + "@example.test").put("Status", "Active")
                        .put("StatusEnum", "Active");
                send(ex, 200, redrockBody(rows, 1));
            } else {
                send(ex, 200, "{\"success\":false,\"Message\":\"stub: unsupported query\"}");
            }
        }

        private ObjectNode roleRow(String id) {
            ObjectNode r = MAPPER.createObjectNode();
            r.put("ID", id).put("Name", "APP-" + id).put("RoleType", "PrincipalList").put("ReadOnly", false)
                    .put("Description", "stub role " + id);
            return r;
        }

        private static String redrockBody(ArrayNode rows, Integer fullCount) {
            ObjectNode root = MAPPER.createObjectNode().put("success", true);
            ObjectNode result = root.putObject("Result");
            result.put("Count", rows.size());
            if (fullCount != null) {
                result.put("FullCount", fullCount);
            }
            result.set("Results", rows);
            return root.toString();
        }

        private void members(HttpExchange ex) throws IOException {
            calls.incrementAndGet();
            String role = param(ex, "name");
            Mode mode = memberMode.getOrDefault(role, Mode.OK);
            if (mode == Mode.FAIL) {
                send(ex, 500, "{\"Message\":\"stub: members unavailable\"}");
                return;
            }
            List<String[]> list = new ArrayList<>(members.getOrDefault(role, List.of()));
            if (mode == Mode.DUPLICATE && !list.isEmpty()) {
                list.add(list.get(0));
            }
            ArrayNode entries = MAPPER.createArrayNode();
            for (String[] m : list) {
                entries.addObject().put("Guid", m[0]).put("Name", m[0]).put("Type", m[1]);
            }
            Integer fullCount = mode == Mode.NO_FULLCOUNT ? null
                    : list.size() + (mode == Mode.WRONG_FULLCOUNT ? 1 : 0);
            ObjectNode container = MAPPER.createObjectNode();
            if (fullCount != null) {
                container.put("FullCount", fullCount);
            }
            ArrayNode results = container.putArray("Results");
            if (mode == Mode.SOFT_ERROR) { // only the nested documented shape carries IsSoftError
                results.addObject().set("Row", entries);
                ObjectNode outer = MAPPER.createObjectNode();
                ObjectNode result = outer.putObject("Result").put("success", true).put("IsSoftError", true);
                result.set("Result", container);
                send(ex, 200, outer.toString());
                return;
            }
            entries.forEach(e -> results.addObject().set("Row", e));
            ObjectNode root = MAPPER.createObjectNode().put("success", true);
            root.set("Result", container);
            send(ex, 200, root.toString());
        }

        private static String param(HttpExchange ex, String name) {
            String q = ex.getRequestURI().getRawQuery();
            for (String pair : q == null ? new String[0] : q.split("&")) {
                if (pair.startsWith(name + "=")) {
                    return java.net.URLDecoder.decode(pair.substring(name.length() + 1), StandardCharsets.UTF_8);
                }
            }
            return null;
        }

        private static void send(HttpExchange ex, int status, String body) throws IOException {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(status, bytes.length);
            try (OutputStream o = ex.getResponseBody()) {
                o.write(bytes);
            }
        }

        @Override
        public void close() {
            stub.close();
        }
    }

    private DbConfig db;

    @BeforeEach
    void setUp() {
        Map<String, String> env = System.getenv();
        assumeTrue(env.get("CYBERARK_IT_PG_HOST") != null && env.get("CYBERARK_IT_PG_DATABASE") != null
                        && env.get("CYBERARK_IT_PG_USERNAME") != null && env.get("CYBERARK_IT_PG_PASSWORD") != null,
                "CYBERARK_IT_PG_* not set: PostgreSQL integration tests skipped");
        db = new DbConfig(env.get("CYBERARK_IT_PG_HOST"), Integer.parseInt(env.getOrDefault("CYBERARK_IT_PG_PORT", "5432")),
                env.get("CYBERARK_IT_PG_DATABASE"), env.get("CYBERARK_IT_PG_USERNAME"), env.get("CYBERARK_IT_PG_PASSWORD"),
                "cyberark_it_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12));
    }

    @AfterEach
    void tearDown() throws Exception {
        if (db != null) {
            try (Connection conn = db.open(); Statement st = conn.createStatement()) {
                st.execute("DROP SCHEMA IF EXISTS " + db.schema() + " CASCADE");
            }
        }
    }

    private Map<String, Object> run(Tenant t) {
        return run(t, PATTERN);
    }

    private Map<String, Object> run(Tenant t, String pattern) {
        return ApproverGroupRun.run(t.client(), db, new ApproverGroupRun.Settings(pattern, 2, 100, 10));
    }

    private String one(String sql) throws Exception {
        try (Connection conn = db.open(); Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            return rs.next() ? rs.getString(1) : null;
        }
    }

    private long count(String sql) throws Exception {
        return Long.parseLong(one(sql));
    }

    private String t(String table) {
        return db.schema() + "." + table;
    }

    private String roleMissing(String roleId) throws Exception {
        return one("SELECT missing_since::text FROM " + t(ApproverGroupRun.RESULT_TABLE) + " WHERE role_id = '"
                + roleId + "'");
    }

    private String memberMissing(String roleId, String guid) throws Exception {
        return one("SELECT missing_since::text FROM " + t(ApproverGroupRun.MEMBER_TABLE) + " WHERE role_id = '"
                + roleId + "' AND \"Guid\" = '" + guid + "'");
    }

    private long rolesMarked() throws Exception {
        return count("SELECT count(*) FROM " + t(ApproverGroupRun.RESULT_TABLE) + " WHERE missing_since IS NOT NULL");
    }

    private long membersMarked() throws Exception {
        return count("SELECT count(*) FROM " + t(ApproverGroupRun.MEMBER_TABLE) + " WHERE missing_since IS NOT NULL");
    }

    private static Map<?, ?> roles(Map<String, Object> run) {
        return (Map<?, ?>) ((Map<?, ?>) run.get("reconciliation")).get("roles");
    }

    private static Map<?, ?> members(Map<String, Object> run) {
        return (Map<?, ?>) ((Map<?, ?>) run.get("reconciliation")).get("members");
    }

    /** R1 (3 users, PASS), R2 (1 user, FAIL), R3 (2 users, PASS) */
    private static Tenant threeRoles() {
        return new Tenant().role("R1", "U1", "U2", "U3").role("R2", "U4").role("R3", "U5", "U6");
    }

    // ---- roles ------------------------------------------------------------------------------------------------

    @Test
    void aRoleNotFoundByACompleteSearchIsMarkedKeepsItsVerdictAndClearsWhenItComesBack() throws Exception {
        try (Tenant tenant = threeRoles()) {
            Map<String, Object> first = run(tenant);
            assertEquals("SUCCESS", first.get("status"), String.valueOf(first));
            assertEquals(true, roles(first).get("performed"));
            assertEquals(0, roles(first).get("marked_missing"));
            String uuidR2 = one("SELECT record_uuid FROM " + t(ApproverGroupRun.RESULT_TABLE) + " WHERE role_id = 'R2'");
            String uuidR3 = one("SELECT record_uuid FROM " + t(ApproverGroupRun.RESULT_TABLE) + " WHERE role_id = 'R3'");

            tenant.roles.remove("R2");
            tenant.roles.remove("R3");
            Map<String, Object> second = run(tenant);
            assertEquals("SUCCESS", second.get("status"));
            assertEquals(2, roles(second).get("marked_missing"));
            assertNotNull(roleMissing("R2"));
            assertNotNull(roleMissing("R3"));
            assertNull(roleMissing("R1"));
            assertEquals("FAIL", one("SELECT outcome FROM " + t(ApproverGroupRun.RESULT_TABLE) + " WHERE role_id = 'R2'"),
                    "the previous FAIL verdict is kept");
            assertEquals("PASS", one("SELECT outcome FROM " + t(ApproverGroupRun.RESULT_TABLE) + " WHERE role_id = 'R3'"),
                    "the previous PASS verdict is kept");
            assertEquals(1, ((ArrayNode) second.get("roles")).size(), "the run's own answer is about what was found");

            String since = roleMissing("R2");
            run(tenant);
            assertEquals(since, roleMissing("R2"), "a repeat keeps the first date");

            tenant.role("R3", "U5", "U6");
            Map<String, Object> back = run(tenant);
            assertEquals("SUCCESS", back.get("status"));
            assertNull(roleMissing("R3"), "cleared by the normal upsert");
            assertEquals(uuidR3, one("SELECT record_uuid FROM " + t(ApproverGroupRun.RESULT_TABLE)
                    + " WHERE role_id = 'R3'"), "the same row");
            assertEquals(uuidR2, one("SELECT record_uuid FROM " + t(ApproverGroupRun.RESULT_TABLE)
                    + " WHERE role_id = 'R2'"));
            assertEquals(3, count("SELECT count(*) FROM " + t(ApproverGroupRun.RESULT_TABLE)), "nothing deleted");
        }
    }

    @Test
    void anUnprovenRoleSearchNeverMarksRoles() throws Exception {
        try (Tenant tenant = threeRoles()) {
            run(tenant);
            tenant.roles.remove("R3");
            for (Mode mode : List.of(Mode.NO_FULLCOUNT, Mode.WRONG_FULLCOUNT)) {
                tenant.searchMode = mode;
                Map<String, Object> r = run(tenant);
                assertEquals(false, roles(r).get("performed"), mode + ": " + r);
                assertTrue(String.valueOf(roles(r).get("reason")).startsWith("not reconciled"), mode.toString());
                assertEquals(0, rolesMarked(), mode + ": nothing marked");
            }
            tenant.searchMode = Mode.OK;
            tenant.duplicateRole = true; // the same role on a page twice: the paging may not be stable
            Map<String, Object> dup = run(tenant);
            assertEquals(false, roles(dup).get("performed"), String.valueOf(dup));
            assertTrue(String.valueOf(roles(dup).get("reason")).contains("repeated role row"));
            assertEquals(0, rolesMarked());

            // the page limit: 2 roles with a page size of 1 and at most 1 page
            tenant.duplicateRole = false;
            Map<String, Object> limited = ApproverGroupRun.run(tenant.client(), db,
                    new ApproverGroupRun.Settings(PATTERN, 2, 1, 1));
            assertEquals("INCOMPLETE", limited.get("status"), String.valueOf(limited));
            assertEquals(false, roles(limited).get("performed"));
        }
    }

    @Test
    void aCheckFailedRoleIsStillPresentAndDoesNotBlockTheOthers() throws Exception {
        try (Tenant tenant = threeRoles()) {
            run(tenant);
            tenant.roles.remove("R3");
            tenant.memberMode.put("R2", Mode.FAIL); // R2's check fails: CHECK_FAILED
            Map<String, Object> r = run(tenant);

            assertEquals("COMPLETED_WITH_FAILURES", r.get("status"));
            assertEquals("CHECK_FAILED", one("SELECT outcome FROM " + t(ApproverGroupRun.RESULT_TABLE)
                    + " WHERE role_id = 'R2'"));
            assertEquals(true, roles(r).get("performed"), "the search was complete");
            assertNull(roleMissing("R2"), "found, so present");
            assertNotNull(roleMissing("R3"), "not found");
            assertNull(memberMissing("R2", "U4"), "R2's members are not reconciled: its list failed");
        }
    }

    @Test
    void aRoleResultThatCannotBeStoredBlocksRoleReconciliation() throws Exception {
        try (Tenant tenant = threeRoles()) {
            run(tenant);
            try (Connection conn = db.open(); Statement st = conn.createStatement()) {
                st.execute("ALTER TABLE " + t(ApproverGroupRun.RESULT_TABLE)
                        + " ADD CONSTRAINT it_refuse_r1 CHECK (role_id <> 'R1') NOT VALID");
            }
            tenant.roles.remove("R3");
            Map<String, Object> r = run(tenant);
            assertEquals("COMPLETED_WITH_FAILURES", r.get("status"));
            assertEquals(false, roles(r).get("performed"));
            assertTrue(String.valueOf(roles(r).get("reason")).contains("could not be stored"));
            assertEquals(0, rolesMarked());
        }
    }

    @Test
    void anotherPatternIsNeverTouched() throws Exception {
        try (Tenant tenant = threeRoles()) {
            run(tenant);
            try (Tenant other = new Tenant().role("O1", "U9")) {
                assertEquals("SUCCESS", run(other, "OTHER-%").get("status"));
            }
            tenant.roles.remove("R3");
            run(tenant);
            assertNotNull(roleMissing("R3"));
            assertNull(roleMissing("O1"), "a result of another pattern is never marked");
            assertEquals("OTHER-%", one("SELECT role_pattern FROM " + t(ApproverGroupRun.RESULT_TABLE)
                    + " WHERE role_id = 'O1'"));
        }
    }

    @Test
    void anInterruptedSearchReconcilesNothingAndReleasesTheLock() throws Exception {
        try (Tenant tenant = threeRoles()) {
            run(tenant);
            tenant.roles.remove("R3");
            tenant.searchDelayMs = 3000;
            java.util.concurrent.atomic.AtomicReference<Map<String, Object>> out =
                    new java.util.concurrent.atomic.AtomicReference<>();
            Thread runner = new Thread(() -> out.set(run(tenant)));
            runner.start();
            waitForLock();
            runner.interrupt();
            runner.join(10_000);

            assertEquals("FAILED", out.get().get("status"), String.valueOf(out.get()));
            assertFalse(out.get().containsKey("reconciliation"));
            assertEquals(0, rolesMarked());
            tenant.searchDelayMs = 0;
            assertEquals("SUCCESS", run(tenant).get("status"), "the lock was released");
            assertNotNull(roleMissing("R3"));
        }
    }

    // ---- members ----------------------------------------------------------------------------------------------

    @Test
    void aCompleteMemberListMarksRemovedMembersAndReturningOnesAreCleared() throws Exception {
        try (Tenant tenant = threeRoles()) {
            run(tenant);
            String uuidU3 = one("SELECT record_uuid FROM " + t(ApproverGroupRun.MEMBER_TABLE)
                    + " WHERE role_id = 'R1' AND \"Guid\" = 'U3'");
            tenant.role("R1", "U1", "U2"); // U3 removed from R1
            Map<String, Object> r = run(tenant);
            assertEquals(3, members(r).get("lists_reconciled"));
            assertEquals(1, members(r).get("marked_missing"));
            assertNotNull(memberMissing("R1", "U3"));
            assertNull(memberMissing("R1", "U1"));
            assertEquals("PASS", one("SELECT outcome FROM " + t(ApproverGroupRun.RESULT_TABLE) + " WHERE role_id = 'R1'"),
                    "the verdict itself comes from the run, as before (2 users meet the minimum of 2)");

            tenant.role("R1", "U1", "U2", "U3");
            run(tenant);
            assertNull(memberMissing("R1", "U3"), "cleared by the normal upsert");
            assertEquals(uuidU3, one("SELECT record_uuid FROM " + t(ApproverGroupRun.MEMBER_TABLE)
                    + " WHERE role_id = 'R1' AND \"Guid\" = 'U3'"), "the same row");
            assertEquals(0, membersMarked());
        }
    }

    @Test
    void nestedRoleMembersAreReconciledOnTheirOwn() throws Exception {
        try (Tenant tenant = new Tenant().role("R1", "U1", "role:N1").nested("N1", "U7", "U8")) {
            Map<String, Object> first = run(tenant);
            assertEquals("SUCCESS", first.get("status"), String.valueOf(first));
            assertEquals(1, count("SELECT count(*) FROM " + t(ApproverGroupRun.MEMBER_TABLE)
                    + " WHERE role_id = 'N1' AND \"Guid\" = 'U8'"));

            tenant.members.put("N1", List.<String[]>of(new String[] {"U7", "User"})); // U8 left the nested role
            Map<String, Object> second = run(tenant);
            assertNotNull(memberMissing("N1", "U8"), "the nested role's own list decides");
            assertNull(memberMissing("N1", "U7"));
            assertNull(memberMissing("R1", "role:N1".substring(5)), "the parent's list is unchanged");
            assertEquals(2, members(second).get("lists_reconciled"));
        }
    }

    @Test
    void anUnprovenMemberListMarksNothingForThatRoleButOthersStillReconcile() throws Exception {
        for (Mode mode : List.of(Mode.SOFT_ERROR, Mode.NO_FULLCOUNT, Mode.WRONG_FULLCOUNT, Mode.DUPLICATE, Mode.FAIL)) {
            setUp();
            try (Tenant tenant = threeRoles()) {
                run(tenant);
                tenant.role("R1", "U1", "U2"); // U3 removed from R1
                tenant.role("R3", "U5");       // U6 removed from R3
                tenant.memberMode.put("R1", mode);
                Map<String, Object> r = run(tenant);

                assertNull(memberMissing("R1", "U3"), mode + ": R1's list cannot be proven, nothing marked");
                assertNotNull(memberMissing("R3", "U6"), mode + ": R3's complete list is still reconciled");
                assertTrue(members(r).get("lists_skipped").toString().contains("R1")
                        || mode == Mode.FAIL, mode + ": " + members(r));
            } finally {
                tearDown();
            }
        }
    }

    @Test
    void aMemberRowThatCannotBeStoredBlocksThatListOnly() throws Exception {
        try (Tenant tenant = threeRoles()) {
            run(tenant);
            try (Connection conn = db.open(); Statement st = conn.createStatement()) {
                st.execute("ALTER TABLE " + t(ApproverGroupRun.MEMBER_TABLE)
                        + " ADD CONSTRAINT it_refuse_u1 CHECK (\"Guid\" <> 'U1') NOT VALID");
            }
            tenant.role("R1", "U1", "U2"); // U3 removed, and U1 cannot be stored
            tenant.role("R3", "U5");       // U6 removed
            Map<String, Object> r = run(tenant);
            assertNull(memberMissing("R1", "U3"), "R1's rows were not all stored");
            assertNotNull(memberMissing("R3", "U6"));
            assertTrue(members(r).get("lists_skipped").toString().contains("could not be stored"));
        }
    }

    // ---- lock and upgrade ---------------------------------------------------------------------------------------

    private void waitForLock() throws Exception {
        for (int i = 0; i < 100; i++) {
            if (count("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted AND classid = "
                    + Integer.toUnsignedLong(ApproverGroupRun.LOCK_SPACE) + " AND objid = " + ApproverGroupRun.LOCK_KEY
                    + " AND objsubid = 2") > 0) {
                return;
            }
            Thread.sleep(50);
        }
        throw new AssertionError("the run never took its lock");
    }

    @Test
    void aSecondRunFailsAtOnceAndTheLockIsFreeAfterwards() throws Exception {
        try (Tenant tenant = threeRoles();
             Connection other = db.open(); Statement st = other.createStatement()) {
            st.execute("SELECT pg_advisory_lock(" + ApproverGroupRun.LOCK_SPACE + ", " + ApproverGroupRun.LOCK_KEY + ")");
            long start = System.nanoTime();
            Map<String, Object> blocked = run(tenant);
            assertEquals("FAILED", blocked.get("status"));
            assertEquals("ALREADY_RUNNING", blocked.get("error_kind"));
            assertTrue((System.nanoTime() - start) / 1_000_000 < 3000, "fails fast");
            assertEquals(0, tenant.calls.get(), "CyberArk is not called");
            st.execute("SELECT pg_advisory_unlock(" + ApproverGroupRun.LOCK_SPACE + ", " + ApproverGroupRun.LOCK_KEY + ")");
            assertEquals("SUCCESS", run(tenant).get("status"));
        }
    }

    @Test
    void tablesOfEarlierVersionsGetTheColumnWithEveryRowKept() throws Exception {
        List<Column> oldMembers = ApproverGroupRun.ROLE_MEMBER_COLUMNS.stream()
                .filter(c -> !c.name().equals(ApproverGroupRun.MISSING_SINCE)).toList();
        List<Column> oldResults = ApproverGroupRun.RESULT_COLUMNS.stream()
                .filter(c -> !c.name().equals(ApproverGroupRun.MISSING_SINCE)).toList();
        RawRecordRepository m = new RawRecordRepository(db.schema(), ApproverGroupRun.MEMBER_TABLE, oldMembers,
                List.of("role_id", "Guid"));
        RawRecordRepository r = new RawRecordRepository(db.schema(), ApproverGroupRun.RESULT_TABLE, oldResults,
                "role_id");
        try (Connection conn = db.open()) {
            m.ensureTable(conn);
            r.ensureTable(conn);
            m.upsert(conn, MAPPER.readTree("{\"role_id\":\"OLD\",\"Guid\":\"UX\",\"Type\":\"User\"}"));
            r.upsert(conn, MAPPER.readTree("{\"role_id\":\"OLD\",\"outcome\":\"PASS\",\"role_pattern\":\"APP-%\"}"));
        }
        String uuid = one("SELECT record_uuid FROM " + t(ApproverGroupRun.RESULT_TABLE) + " WHERE role_id = 'OLD'");

        try (Tenant tenant = threeRoles()) {
            Map<String, Object> first = run(tenant);
            assertEquals("SUCCESS", first.get("status"), String.valueOf(first));
            assertEquals(uuid, one("SELECT record_uuid FROM " + t(ApproverGroupRun.RESULT_TABLE)
                    + " WHERE role_id = 'OLD'"), "the old row is kept");
            assertNotNull(roleMissing("OLD"), "and, not found by this complete search, marked");
            assertEquals("PASS", one("SELECT outcome FROM " + t(ApproverGroupRun.RESULT_TABLE) + " WHERE role_id = 'OLD'"));
            assertNull(memberMissing("OLD", "UX"), "its member list was not fetched, so it is not reconciled");
            assertEquals(1, count("SELECT count(*) FROM " + t(ApproverGroupRun.MEMBER_TABLE) + " WHERE role_id = 'OLD'"));
            assertEquals("SUCCESS", run(tenant).get("status"), "the upgrade is safe to repeat");
        }
    }
}
