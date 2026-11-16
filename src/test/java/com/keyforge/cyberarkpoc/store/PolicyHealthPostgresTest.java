package com.keyforge.cyberarkpoc.store;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyforge.cyberarkpoc.MockFixture;
import com.keyforge.cyberarkpoc.check.PolicyHealthRun;
import com.keyforge.cyberarkpoc.config.PolicyConfig.Api;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer.Fault;
import com.keyforge.cyberarkpoc.mock.MockDataset;
import com.keyforge.cyberarkpoc.mock.SampleData;
import com.keyforge.cyberarkpoc.rest.ExtractionRestServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Use Case 2 end to end against the local mock and a REAL PostgreSQL, in a throwaway schema dropped afterwards. Runs
 * only when the {@code CYBERARK_IT_PG_*} variables point at a test database; otherwise every test is skipped.
 */
class PolicyHealthPostgresTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

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

    private long count(String sql) throws Exception {
        try (Connection conn = db.open(); Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            rs.next();
            return rs.getLong(1);
        }
    }

    private Set<String> columns(String table) throws Exception {
        try (Connection conn = db.open(); Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(
                "SELECT column_name FROM information_schema.columns WHERE table_schema = '" + db.schema()
                        + "' AND table_name = '" + table + "'")) {
            Set<String> names = new LinkedHashSet<>();
            while (rs.next()) {
                names.add(rs.getString(1));
            }
            return names;
        }
    }

    private String columnType(String table, String column) throws Exception {
        try (Connection conn = db.open(); Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(
                "SELECT data_type FROM information_schema.columns WHERE table_schema = '" + db.schema()
                        + "' AND table_name = '" + table + "' AND column_name = '" + column + "'")) {
            return rs.next() ? rs.getString(1) : null;
        }
    }

    private String t(String table) {
        return db.schema() + "." + table;
    }

    @Test
    void uapRunStoresEveryPolicyAndItsOutcomeAndReRunsUpdateInPlace() throws Exception {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            Map<String, Object> first = PolicyHealthRun.run(f.policyClient(Api.UAP), db);

            assertEquals("SUCCESS", first.get("status"), String.valueOf(first));
            assertEquals("FINDINGS", first.get("health"));
            assertEquals(Map.of("FINDING", 3L, "NO_FINDING", 4L, "CANNOT_VERIFY", 1L), first.get("summary"));
            assertEquals(3, ((List<?>) first.get("findings")).size());
            assertEquals(Set.of("record_uuid", "extracted_at", "metadata", "principals", "delegationClassification",
                    "policy_id", "policy_api"), columns(PolicyHealthRun.POLICY_TABLE),
                    "one column per top-level field received, plus policy_id and policy_api");
            assertEquals("jsonb", columnType(PolicyHealthRun.POLICY_TABLE, "metadata"));
            assertEquals(8, count("SELECT count(*) FROM " + t(PolicyHealthRun.POLICY_TABLE)));
            assertEquals(1, count("SELECT count(*) FROM " + t(PolicyHealthRun.POLICY_TABLE) + " WHERE policy_id = 'pol-002'"
                    + " AND metadata->'status'->>'statusCode' = 'MOCK_TARGET_UNREACHABLE' AND policy_api = 'uap'"));
            assertEquals(1, count("SELECT count(*) FROM pg_indexes WHERE schemaname = '" + db.schema()
                    + "' AND tablename = 'uap_policy' AND indexdef LIKE 'CREATE UNIQUE INDEX%(policy_api, policy_id)'"),
                    "keyed on the API and the policy id");
            assertEquals(8, count("SELECT count(*) FROM " + t(PolicyHealthRun.RESULT_TABLE)));
            assertEquals(1, count("SELECT count(*) FROM " + t(PolicyHealthRun.RESULT_TABLE) + " WHERE policy_id = 'pol-002'"
                    + " AND outcome = 'FINDING' AND status = 'Error' AND status_code = 'MOCK_TARGET_UNREACHABLE'"
                    + " AND status_description LIKE 'MOCK: the target AWS account%' AND retrieval_complete"));
            assertEquals(1, count("SELECT count(*) FROM " + t(PolicyHealthRun.RESULT_TABLE) + " WHERE policy_id = 'pol-008'"
                    + " AND outcome = 'CANNOT_VERIFY' AND reason = 'undocumented status ''Disabled'''"));
            assertEquals(0, count("SELECT count(*) FROM (SELECT row_to_json(x)::text AS j FROM " + t(PolicyHealthRun.POLICY_TABLE)
                    + " x UNION ALL SELECT row_to_json(y)::text FROM " + t(PolicyHealthRun.RESULT_TABLE) + " y) z "
                    + "WHERE j LIKE '%mock-policy-token-%' OR j LIKE '%" + MockCyberArkServer.MOCK_CLIENT_SECRET + "%'"),
                    "no token or client secret stored");
            assertFalse(MAPPER.writeValueAsString(first).contains("mock-policy-token-"), "no token in the response");
            try (Connection conn = db.open(); Statement st = conn.createStatement()) {
                st.execute("CREATE TABLE " + t("snap_p") + " AS SELECT policy_id, record_uuid FROM "
                        + t(PolicyHealthRun.POLICY_TABLE));
            }

            Map<String, Object> second = PolicyHealthRun.run(f.policyClient(Api.UAP), db);

            @SuppressWarnings("unchecked")
            Map<String, Map<String, Integer>> stored = (Map<String, Map<String, Integer>>) second.get("stored");
            assertEquals(Map.of("inserted", 0, "updated", 8, "failed", 0), stored.get(PolicyHealthRun.POLICY_TABLE));
            assertEquals(Map.of("inserted", 0, "updated", 8, "failed", 0), stored.get(PolicyHealthRun.RESULT_TABLE));
            assertEquals(List.of(), second.get("schema_changes"));
            assertEquals(0, count("SELECT count(*) FROM " + t(PolicyHealthRun.POLICY_TABLE) + " p JOIN " + t("snap_p")
                    + " s USING (policy_id) WHERE p.record_uuid <> s.record_uuid"), "uuids unchanged");
        }
    }

    @Test
    void scaRunUsesTheNumericStatusAndStoresTheScaShape() throws Exception {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            Map<String, Object> result = PolicyHealthRun.run(f.policyClient(Api.SCA), db);

            assertEquals("SUCCESS", result.get("status"), String.valueOf(result));
            assertEquals("sca", result.get("policy_api"));
            assertEquals(Map.of("FINDING", 3L, "NO_FINDING", 3L, "CANNOT_VERIFY", 2L), result.get("summary"),
                    "Suspended and Disabled have no documented SCA number");
            assertTrue(columns(PolicyHealthRun.POLICY_TABLE).containsAll(List.of("policyId", "status", "faultCode",
                    "statusTooltipMessage", "cloudProvider", "policy_id")));
            assertEquals("bigint", columnType(PolicyHealthRun.POLICY_TABLE, "status"));
            assertEquals(1, count("SELECT count(*) FROM " + t(PolicyHealthRun.RESULT_TABLE) + " WHERE policy_id = 'pol-003'"
                    + " AND outcome = 'FINDING' AND status = 'Warning (5)' AND policy_api = 'sca'"));
        }
    }

    @Test
    void anIncompleteListIsStoredButNeverReportedAsAllHealthy() throws Exception {
        MockDataset healthy = new MockDataset().policyPageSize(2)
                .policy("ok-1", "MOCK-OK-1", "Active", null, null)
                .policy("ok-2", "MOCK-OK-2", "Active", null, null)
                .policy("ok-3", "MOCK-OK-3", "Suspended", null, null);
        try (MockFixture f = MockFixture.start(healthy)) {
            Map<String, Object> complete = PolicyHealthRun.run(f.policyClient(Api.UAP), db);
            assertEquals("SUCCESS", complete.get("status"));
            assertEquals("ALL_HEALTHY", complete.get("health"), "only after a complete retrieval");

            f.mock.fail(MockCyberArkServer.POLICIES, Fault.WRONG_COUNT);
            Map<String, Object> incomplete = PolicyHealthRun.run(f.policyClient(Api.UAP), db);

            assertEquals("INCOMPLETE", incomplete.get("status"));
            assertEquals("UNDETERMINED", incomplete.get("health"));
            assertEquals(PolicyHealthRun.INCOMPLETE_NOTE, incomplete.get("health_note"));
            assertEquals(3, count("SELECT count(*) FROM " + t(PolicyHealthRun.RESULT_TABLE) + " WHERE NOT retrieval_complete"));
        }
    }

    @Test
    void findingsOnAnIncompleteListAreStillReported() throws Exception {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.POLICIES, Fault.REPEAT_NEXT_TOKEN);
            Map<String, Object> result = PolicyHealthRun.run(f.policyClient(Api.UAP), db);

            assertEquals("INCOMPLETE", result.get("status"));
            assertEquals("FINDINGS", result.get("health"));
            assertEquals(PolicyHealthRun.INCOMPLETE_NOTE, result.get("health_note"));
        }
    }

    @Test
    void aFailedRetrievalStoresNothingAndConcludesNothing() throws Exception {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.POLICIES, Fault.HTTP_500);
            Map<String, Object> result = PolicyHealthRun.run(f.policyClient(Api.UAP), db);

            assertEquals("FAILED", result.get("status"));
            assertEquals("HTTP_STATUS", result.get("error_kind"));
            assertEquals(500, result.get("http_status"));
            assertEquals("UNDETERMINED", result.get("health"));
            assertFalse(result.containsKey("summary"));
            assertEquals(0, count("SELECT count(*) FROM " + t(PolicyHealthRun.POLICY_TABLE)));
            assertEquals(0, count("SELECT count(*) FROM " + t(PolicyHealthRun.RESULT_TABLE)));
        }
    }

    @Test
    void aPolicyWithoutIdIsReportedButNotStored() throws Exception {
        MockDataset data = new MockDataset()
                .policy("p-1", "MOCK-1", "Active", null, null)
                .policy(null, "MOCK-no-id", "Error", "MOCK_X", "MOCK: broken");
        try (MockFixture f = MockFixture.start(data)) {
            Map<String, Object> result = PolicyHealthRun.run(f.policyClient(Api.UAP), db);

            assertEquals("COMPLETED_WITH_FAILURES", result.get("status"));
            assertEquals("FINDINGS", result.get("health"), "the finding is reported even without an id");
            assertEquals(1, count("SELECT count(*) FROM " + t(PolicyHealthRun.POLICY_TABLE)));
        }
    }

    @Test
    void theRestRouteAnswersWithTheRunAndIsListed() throws Exception {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            ExtractionRestServer rest = new ExtractionRestServer(
                    new ExtractionRestServer.Settings("127.0.0.1", 0, "rest-user", "rest-pass"), () -> null, Map.of(),
                    Map.of("ispss/policy-health", new ExtractionRestServer.StandaloneRoute("use case 2",
                            () -> PolicyHealthRun.run(f.policyClient(Api.UAP), db))));
            rest.start();
            try {
                HttpClient http = HttpClient.newHttpClient();
                String auth = "Basic " + Base64.getEncoder().encodeToString("rest-user:rest-pass"
                        .getBytes(StandardCharsets.UTF_8));
                HttpResponse<String> run = http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + rest.port()
                        + "/cyberark-extract/ispss/policy-health")).header("Authorization", auth).GET().build(),
                        HttpResponse.BodyHandlers.ofString());
                HttpResponse<String> usage = http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"
                        + rest.port() + "/cyberark-extract")).header("Authorization", auth).GET().build(),
                        HttpResponse.BodyHandlers.ofString());

                assertEquals(200, run.statusCode());
                assertEquals("SUCCESS", run.headers().firstValue("X-KF-Run-Status").orElse(""));
                JsonNode body = MAPPER.readTree(run.body());
                assertEquals("ispss/policy-health", body.get("route").asText());
                assertEquals("FINDINGS", body.get("health").asText());
                assertEquals(8, body.get("retrieval").get("received").asInt());
                assertTrue(MAPPER.readTree(usage.body()).get("routes").has("ispss/policy-health"));
            } finally {
                rest.stop();
            }
        }
    }
    // ---- (policy_api, policy_id) key and the upgrade of tables from earlier versions ----------------------------

    private String one(String sql) throws Exception {
        try (Connection conn = db.open(); Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            return rs.next() ? rs.getString(1) : null;
        }
    }

    /** The column sets of the unique indexes of a table, e.g. "policy_api,policy_id". */
    private Set<String> uniqueKeys(String table) throws Exception {
        try (Connection conn = db.open(); Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(
                "SELECT (SELECT string_agg(a.attname::text, ',' ORDER BY a.attname::text) FROM pg_attribute a "
                        + "WHERE a.attrelid = c.oid AND a.attnum = ANY(i.indkey)) FROM pg_index i "
                        + "JOIN pg_class c ON c.oid = i.indrelid JOIN pg_namespace n ON n.oid = c.relnamespace "
                        + "WHERE n.nspname = '" + db.schema() + "' AND c.relname = '" + table + "' AND i.indisunique "
                        + "AND NOT i.indisprimary")) {
            Set<String> keys = new LinkedHashSet<>();
            while (rs.next()) {
                keys.add(rs.getString(1));
            }
            return keys;
        }
    }

    /**
     * Creates both tables exactly as earlier versions did (keyed on policy_id alone, through the same store classes)
     * and stores two UAP policies in them: pol-001 (also returned by the mock) and pol-gone (no longer returned).
     */
    private void createOldTables(String gonePolicyApi) throws Exception {
        GenericRecordStore oldPolicies = new GenericRecordStore(db.schema(), PolicyHealthRun.POLICY_TABLE,
                List.of(PolicyHealthRun.KEY));
        RawRecordRepository oldResults = new RawRecordRepository(db.schema(), PolicyHealthRun.RESULT_TABLE,
                PolicyHealthRun.RESULT_COLUMNS.stream().filter(c -> !c.name().equals(PolicyHealthRun.MISSING_SINCE))
                        .toList(), PolicyHealthRun.KEY);
        List<JsonNode> records = List.of(
                MAPPER.readTree("{\"policy_id\":\"pol-001\",\"policy_api\":\"uap\",\"metadata\":{\"name\":\"old\"}}"),
                MAPPER.readTree("{\"policy_id\":\"pol-gone\",\"policy_api\":" + gonePolicyApi
                        + ",\"metadata\":{\"name\":\"gone\"}}"));
        try (Connection conn = db.open()) {
            oldPolicies.ensureTable(conn);
            oldResults.ensureTable(conn);
            GenericRecordStore.Prepared prepared = oldPolicies.prepare(conn, records);
            for (JsonNode r : records) {
                oldPolicies.upsert(conn, prepared, r);
                oldResults.upsert(conn, MAPPER.readTree("{\"policy_id\":\"" + r.get("policy_id").asText()
                        + "\",\"policy_api\":" + r.get("policy_api") + ",\"outcome\":\"NO_FINDING\"}"));
            }
        }
        assertEquals(Set.of("policy_id"), uniqueKeys(PolicyHealthRun.POLICY_TABLE), "the old key");
        assertEquals(Set.of("policy_id"), uniqueKeys(PolicyHealthRun.RESULT_TABLE), "the old key");
        assertFalse(columns(PolicyHealthRun.RESULT_TABLE).contains(PolicyHealthRun.MISSING_SINCE), "no column yet");
    }

    @Test
    void uapAndScaPoliciesWithTheSameIdAreStoredSideBySide() throws Exception {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            Map<String, Object> uap = PolicyHealthRun.run(f.policyClient(Api.UAP), db);
            Map<String, Object> sca = PolicyHealthRun.run(f.policyClient(Api.SCA), db);
            assertEquals("SUCCESS", uap.get("status"), String.valueOf(uap));
            assertEquals("SUCCESS", sca.get("status"), String.valueOf(sca));
            assertEquals(Map.of("inserted", 8, "updated", 0, "failed", 0),
                    ((Map<?, ?>) sca.get("stored")).get(PolicyHealthRun.POLICY_TABLE), "SCA's pol-001..008 are new rows");

            for (String table : List.of(PolicyHealthRun.POLICY_TABLE, PolicyHealthRun.RESULT_TABLE)) {
                assertEquals(16, count("SELECT count(*) FROM " + t(table)), table + ": 8 UAP + 8 SCA");
                assertEquals(8, count("SELECT count(*) FROM " + t(table) + " WHERE policy_api = 'uap'"), table);
                assertEquals(8, count("SELECT count(*) FROM " + t(table) + " WHERE policy_api = 'sca'"), table);
                assertEquals(Set.of("policy_api,policy_id"), uniqueKeys(table), table);
            }
            // each API keeps its own record shape and its own outcome for the same id
            assertEquals("Error", one("SELECT metadata->'status'->>'status' FROM " + t(PolicyHealthRun.POLICY_TABLE)
                    + " WHERE policy_api = 'uap' AND policy_id = 'pol-002'"));
            assertEquals("4", one("SELECT status FROM " + t(PolicyHealthRun.POLICY_TABLE)
                    + " WHERE policy_api = 'sca' AND policy_id = 'pol-002'"));
            assertEquals("Error", one("SELECT status FROM " + t(PolicyHealthRun.RESULT_TABLE)
                    + " WHERE policy_api = 'uap' AND policy_id = 'pol-002'"));
            assertEquals("Error (4)", one("SELECT status FROM " + t(PolicyHealthRun.RESULT_TABLE)
                    + " WHERE policy_api = 'sca' AND policy_id = 'pol-002'"));

            String uapUuid = one("SELECT record_uuid FROM " + t(PolicyHealthRun.POLICY_TABLE)
                    + " WHERE policy_api = 'uap' AND policy_id = 'pol-001'");
            Map<String, Object> again = PolicyHealthRun.run(f.policyClient(Api.UAP), db);
            assertEquals(Map.of("inserted", 0, "updated", 8, "failed", 0),
                    ((Map<?, ?>) again.get("stored")).get(PolicyHealthRun.POLICY_TABLE), "the UAP rows are updated");
            assertEquals(16, count("SELECT count(*) FROM " + t(PolicyHealthRun.POLICY_TABLE)));
            assertEquals(uapUuid, one("SELECT record_uuid FROM " + t(PolicyHealthRun.POLICY_TABLE)
                    + " WHERE policy_api = 'uap' AND policy_id = 'pol-001'"), "the same row, updated in place");
            assertEquals(8, count("SELECT count(*) FROM " + t(PolicyHealthRun.RESULT_TABLE) + " WHERE policy_api = 'sca'"),
                    "the SCA results are untouched by a UAP run");
        }
    }

    @Test
    void tablesOfEarlierVersionsMoveToTheNewKeyWithoutLosingARow() throws Exception {
        createOldTables("\"uap\"");
        String oldUuid = one("SELECT record_uuid FROM " + t(PolicyHealthRun.POLICY_TABLE) + " WHERE policy_id = 'pol-001'");

        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            Map<String, Object> first = PolicyHealthRun.run(f.policyClient(Api.UAP), db);
            assertEquals("SUCCESS", first.get("status"), String.valueOf(first));
            assertTrue(first.get("schema_changes").toString().contains(
                    "uap_policy: unique key moved from (policy_id) to (policy_api, policy_id)"), first.toString());
            assertTrue(first.get("schema_changes").toString().contains("uap_policy_health_result: unique key moved"));
            assertTrue(first.get("schema_changes").toString().contains(
                    "uap_policy_health_result: added missing_since (NULL on every existing row)"), first.toString());
            assertEquals("timestamp with time zone", columnType(PolicyHealthRun.RESULT_TABLE,
                    PolicyHealthRun.MISSING_SINCE));
            assertEquals(1, count("SELECT count(*) FROM " + t(PolicyHealthRun.RESULT_TABLE)
                    + " WHERE missing_since IS NOT NULL AND policy_id = 'pol-gone'"),
                    "the old row the complete run did not return is marked, not deleted");
            assertEquals(0, count("SELECT count(*) FROM " + t(PolicyHealthRun.RESULT_TABLE)
                    + " WHERE missing_since IS NOT NULL AND policy_id <> 'pol-gone'"));
            assertEquals(Map.of("inserted", 7, "updated", 1, "failed", 0),
                    ((Map<?, ?>) first.get("stored")).get(PolicyHealthRun.POLICY_TABLE), "the old pol-001 is updated");

            for (String table : List.of(PolicyHealthRun.POLICY_TABLE, PolicyHealthRun.RESULT_TABLE)) {
                assertEquals(Set.of("policy_api,policy_id"), uniqueKeys(table), table + ": only the new key");
                assertEquals(9, count("SELECT count(*) FROM " + t(table)), table + ": 8 policies + the old pol-gone");
                assertEquals(1, count("SELECT count(*) FROM " + t(table) + " WHERE policy_id = 'pol-gone'"),
                        table + ": a row no longer returned is kept");
            }
            assertEquals(oldUuid, one("SELECT record_uuid FROM " + t(PolicyHealthRun.POLICY_TABLE)
                    + " WHERE policy_id = 'pol-001'"), "the old row itself is updated, not replaced");
            assertEquals("NO", one("SELECT is_nullable FROM information_schema.columns WHERE table_schema = '"
                    + db.schema() + "' AND table_name = '" + PolicyHealthRun.RESULT_TABLE
                    + "' AND column_name = 'policy_api'"), "as a new result table");

            // the upgrade happens once; later runs (UAP or SCA) change nothing in the keys
            Map<String, Object> second = PolicyHealthRun.run(f.policyClient(Api.UAP), db);
            assertEquals("SUCCESS", second.get("status"));
            assertFalse(second.get("schema_changes").toString().contains("unique key moved"), second.toString());
            assertFalse(second.get("schema_changes").toString().contains("missing_since"), "added once only");
            Map<String, Object> sca = PolicyHealthRun.run(f.policyClient(Api.SCA), db);
            assertEquals("SUCCESS", sca.get("status"), String.valueOf(sca));
            assertFalse(sca.get("schema_changes").toString().contains("unique key moved"));
            assertEquals(17, count("SELECT count(*) FROM " + t(PolicyHealthRun.POLICY_TABLE)),
                    "8 UAP + pol-gone + 8 SCA side by side");
        }
    }

    @Test
    void anOldRowWithoutItsApiStopsTheUpgradeAndChangesNothing() throws Exception {
        createOldTables("null");

        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            Map<String, Object> result = PolicyHealthRun.run(f.policyClient(Api.UAP), db);

            assertEquals("FAILED", result.get("status"), String.valueOf(result));
            assertEquals("DATABASE", result.get("error_kind"));
            assertTrue(String.valueOf(result.get("error")).contains("1 row(s) have no policy_api"), result.toString());
            assertEquals(0, f.mock.requestCount(MockCyberArkServer.POLICIES), "CyberArk is not called");
        }
        for (String table : List.of(PolicyHealthRun.POLICY_TABLE, PolicyHealthRun.RESULT_TABLE)) {
            assertEquals(Set.of("policy_id"), uniqueKeys(table), table + ": the old key is still in place");
            assertEquals(2, count("SELECT count(*) FROM " + t(table)), table + ": every row kept");
        }
        assertEquals("old", one("SELECT metadata->>'name' FROM " + t(PolicyHealthRun.POLICY_TABLE)
                + " WHERE policy_id = 'pol-001'"), "nothing was updated");
    }
    // ---- policies no longer returned: missing_since, reconciliation and the per-API run lock -------------------

    /** UAP/SCA policies with these ids; C is in Error, the others Active. */
    private static MockDataset policies(String... ids) {
        MockDataset data = new MockDataset();
        for (String id : ids) {
            data.policy(id, "MOCK-" + id, id.equals("C") ? "Error" : "Active", id.equals("C") ? "MOCK_C" : null,
                    null);
        }
        return data;
    }

    private Map<String, Object> run(Api api, MockDataset data) {
        try (MockFixture f = MockFixture.start(data)) {
            return PolicyHealthRun.run(f.policyClient(api), db);
        }
    }

    private Map<String, Object> uap(String... ids) {
        return run(Api.UAP, policies(ids));
    }

    private String missingSince(String api, String id) throws Exception {
        return one("SELECT missing_since::text FROM " + t(PolicyHealthRun.RESULT_TABLE) + " WHERE policy_api = '"
                + api + "' AND policy_id = '" + id + "'");
    }

    private String result(String api, String id, String column) throws Exception {
        return one("SELECT " + column + "::text FROM " + t(PolicyHealthRun.RESULT_TABLE) + " WHERE policy_api = '"
                + api + "' AND policy_id = '" + id + "'");
    }

    private static Map<?, ?> reconciliation(Map<String, Object> run) {
        return (Map<?, ?>) run.get("reconciliation");
    }

    private long markedMissing() throws Exception {
        return count("SELECT count(*) FROM " + t(PolicyHealthRun.RESULT_TABLE) + " WHERE missing_since IS NOT NULL");
    }

    @Test
    void aPolicyNotReturnedByACompleteUapRunIsMarkedAndKeepsItsLastOutcome() throws Exception {
        Map<String, Object> first = uap("A", "B", "C", "D");
        assertEquals("SUCCESS", first.get("status"));
        assertEquals(Map.of("policy_api", "uap", "performed", true, "marked_missing", 0,
                "reason", reconciliation(first).get("reason")), reconciliation(first));
        String uuidC = result("uap", "C", "record_uuid");

        Map<String, Object> second = uap("A", "B", "D");
        assertEquals("SUCCESS", second.get("status"));
        assertEquals(true, reconciliation(second).get("performed"));
        assertEquals(1, reconciliation(second).get("marked_missing"));
        assertTrue(missingSince("uap", "C") != null, "C was not returned by a complete run");
        for (String id : List.of("A", "B", "D")) {
            assertEquals(null, missingSince("uap", id), id + " is still returned");
        }
        assertEquals("FINDING", result("uap", "C", "outcome"), "C keeps its last outcome");
        assertEquals(uuidC, result("uap", "C", "record_uuid"), "and its row");
        assertEquals(4, count("SELECT count(*) FROM " + t(PolicyHealthRun.RESULT_TABLE)), "nothing deleted");
        assertEquals(4, count("SELECT count(*) FROM " + t(PolicyHealthRun.POLICY_TABLE)), "raw records kept too");
        // the run's own answer is about what CyberArk returned: C is neither a finding nor counted
        assertEquals(Map.of("FINDING", 0L, "NO_FINDING", 3L, "CANNOT_VERIFY", 0L), second.get("summary"));
        assertEquals("ALL_HEALTHY", second.get("health"));
        assertEquals(3, ((List<?>) second.get("policies")).size());
    }

    @Test
    void theMarkStaysPutOnRepeatsAndIsClearedWhenThePolicyComesBack() throws Exception {
        uap("A", "B", "C", "D");
        uap("A", "B", "D");
        String since = missingSince("uap", "C");
        String uuidC = result("uap", "C", "record_uuid");
        String extractedC = result("uap", "C", "extracted_at");

        Map<String, Object> repeat = uap("A", "B", "D");
        assertEquals(0, reconciliation(repeat).get("marked_missing"), "already marked");
        assertEquals(since, missingSince("uap", "C"), "the first time it went missing is kept");

        Map<String, Object> back = uap("A", "B", "C", "D");
        assertEquals("SUCCESS", back.get("status"));
        assertEquals(null, missingSince("uap", "C"), "cleared by the normal upsert");
        assertEquals(uuidC, result("uap", "C", "record_uuid"), "the same row, updated in place");
        assertEquals(1, count("SELECT count(*) FROM " + t(PolicyHealthRun.RESULT_TABLE) + " WHERE policy_id = 'C'"));
        assertEquals(1, count("SELECT count(*) FROM " + t(PolicyHealthRun.RESULT_TABLE) + " WHERE policy_api = 'uap' "
                + "AND policy_id = 'C' AND extracted_at > '" + extractedC + "'::timestamptz"), "extracted_at updated");
        assertEquals("FINDING", result("uap", "C", "outcome"));
        assertEquals(0, markedMissing());
    }

    @Test
    void uapReconciliationNeverTouchesScaAndScaDoesNotReconcile() throws Exception {
        Map<String, Object> scaFirst = run(Api.SCA, policies("A", "B", "C", "D"));
        assertEquals("SUCCESS", scaFirst.get("status"), String.valueOf(scaFirst));
        uap("A", "B", "C", "D");
        uap("A", "B", "D");
        assertTrue(missingSince("uap", "C") != null);
        assertEquals(null, missingSince("sca", "C"), "the SCA row with the same id is untouched");

        Map<String, Object> scaSecond = run(Api.SCA, policies("A", "B", "D"));
        assertEquals("SUCCESS", scaSecond.get("status"));
        assertEquals(Map.of("policy_api", "sca", "performed", false, "marked_missing", 0,
                "reason", PolicyHealthRun.SCA_NOT_RECONCILED), reconciliation(scaSecond));
        assertEquals(null, missingSince("sca", "C"), "SCA never marks: its completeness cannot be shown");
        assertEquals(1, markedMissing(), "only the UAP C");
    }

    @Test
    void incompleteRunsNeverReconcile() throws Exception {
        uap("A", "B", "C", "D");
        record Case(String name, Fault fault, int pageSize, int maxPages, String... ids) {
        }
        List<Case> cases = List.of(
                new Case("wrong total", Fault.WRONG_COUNT, 0, 0, "A", "B", "D"),
                new Case("no total", Fault.NO_TOTAL, 0, 0, "A", "B", "D"),
                new Case("repeated nextToken", Fault.REPEAT_NEXT_TOKEN, 1, 0, "A", "B", "D"),
                new Case("failedServices", Fault.FAILED_SERVICES, 0, 0, "A", "B", "D"),
                new Case("page limit", null, 1, 1, "A", "B", "D"),
                new Case("duplicate id", null, 0, 0, "A", "B", "D", "D"));
        for (Case c : cases) {
            MockDataset data = policies(c.ids());
            if (c.pageSize() > 0) {
                data.policyPageSize(c.pageSize());
            }
            try (MockFixture f = MockFixture.start(data)) {
                if (c.fault() != null) {
                    f.mock.fail(MockCyberArkServer.POLICIES, c.fault());
                }
                com.keyforge.cyberarkpoc.client.PolicyClient client = c.maxPages() > 0
                        ? new com.keyforge.cyberarkpoc.client.PolicyClient(MockFixture.policyConfig(f.mock.rootUrl(),
                                Api.UAP, MockCyberArkServer.MOCK_CLIENT_SECRET, 50, c.maxPages()))
                        : f.policyClient(Api.UAP);
                Map<String, Object> r = PolicyHealthRun.run(client, db);

                assertEquals("INCOMPLETE", r.get("status"), c.name() + ": " + r);
                assertEquals(false, reconciliation(r).get("performed"), c.name());
                assertTrue(String.valueOf(reconciliation(r).get("reason")).contains("INCOMPLETE"), c.name());
                assertEquals(0, markedMissing(), c.name() + ": nothing marked");
            }
        }
    }

    @Test
    void failedRunsAndStorageFailuresNeverReconcile() throws Exception {
        uap("A", "B", "C", "D");
        for (Fault fault : List.of(Fault.HTTP_500, Fault.MALFORMED_JSON)) {
            try (MockFixture f = MockFixture.start(policies("A", "B", "D"))) {
                f.mock.fail(MockCyberArkServer.POLICIES, fault);
                Map<String, Object> r = PolicyHealthRun.run(f.policyClient(Api.UAP), db);
                assertEquals("FAILED", r.get("status"), fault + ": " + r);
                assertFalse(r.containsKey("reconciliation"), fault + ": a failed run stops before reconciling");
            }
        }
        try (MockFixture f = MockFixture.start(policies("A", "B", "D"))) { // a timeout
            f.mock.fail(MockCyberArkServer.POLICIES, Fault.DELAY);
            com.keyforge.cyberarkpoc.client.PolicyClient slow = new com.keyforge.cyberarkpoc.client.PolicyClient(
                    new com.keyforge.cyberarkpoc.config.PolicyConfig(Api.UAP, URI.create(f.mock.rootUrl() + "/api"),
                            URI.create(f.mock.rootUrl() + com.keyforge.cyberarkpoc.config.PolicyConfig.TOKEN_PATH
                                    + MockCyberArkServer.MOCK_POLICY_APP_ID), MockCyberArkServer.MOCK_CLIENT_ID,
                            MockCyberArkServer.MOCK_CLIENT_SECRET, 50, 10, java.time.Duration.ofSeconds(1)));
            Map<String, Object> r = PolicyHealthRun.run(slow, db);
            assertEquals("FAILED", r.get("status"), String.valueOf(r));
            assertEquals("TRANSPORT", r.get("error_kind"));
        }
        assertEquals(0, markedMissing(), "no failed run marks anything");

        MockDataset noId = policies("A", "B", "D").policy(null, "MOCK-no-id", "Active", null, null);
        Map<String, Object> withoutId = run(Api.UAP, noId);
        assertEquals("COMPLETED_WITH_FAILURES", withoutId.get("status"));
        assertEquals(false, reconciliation(withoutId).get("performed"));
        assertEquals(0, markedMissing(), "a policy without an id could be C");

        try (Connection conn = db.open(); Statement st = conn.createStatement()) {
            st.execute("ALTER TABLE " + t(PolicyHealthRun.RESULT_TABLE)
                    + " ADD CONSTRAINT it_refuse_b CHECK (policy_id <> 'B') NOT VALID");
        }
        Map<String, Object> storeFailed = uap("A", "B", "D");
        assertEquals("COMPLETED_WITH_FAILURES", storeFailed.get("status"), String.valueOf(storeFailed));
        assertEquals(false, reconciliation(storeFailed).get("performed"));
        assertEquals(0, markedMissing(), "a row that could not be stored blocks reconciliation");
    }

    @Test
    void anInterruptedRunCannotReconcileAndReleasesItsLock() throws Exception {
        uap("A", "B", "C", "D");
        try (MockFixture f = MockFixture.start(policies("A", "B", "D"))) {
            f.mock.fail(MockCyberArkServer.POLICIES, Fault.DELAY); // the answer takes 2.5 s
            java.util.concurrent.atomic.AtomicReference<Map<String, Object>> out =
                    new java.util.concurrent.atomic.AtomicReference<>();
            Thread runner = new Thread(() -> out.set(PolicyHealthRun.run(f.policyClient(Api.UAP), db)));
            runner.start();
            waitForLock(PolicyHealthRun.LOCK_UAP);
            runner.interrupt();
            runner.join(10_000);

            assertEquals("FAILED", out.get().get("status"), String.valueOf(out.get()));
            assertFalse(out.get().containsKey("reconciliation"));
        }
        assertEquals(0, markedMissing());
        assertEquals("SUCCESS", uap("A", "B", "D").get("status"), "the lock was released");
        assertEquals(1, markedMissing());
    }

    /** Waits until a session holds the run lock of this API. */
    private void waitForLock(int apiKey) throws Exception {
        for (int i = 0; i < 100; i++) {
            if (count("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted AND classid = "
                    + Integer.toUnsignedLong(PolicyHealthRun.LOCK_SPACE) + " AND objid = " + apiKey + " AND objsubid = 2")
                    > 0) {
                return;
            }
            Thread.sleep(50);
        }
        throw new AssertionError("the run never took its lock");
    }

    @Test
    void aSecondRunOfTheSameApiFailsAtOnceWhileTheOtherApiRuns() throws Exception {
        // another process: a different session holding the UAP run lock
        try (Connection other = db.open(); Statement st = other.createStatement()) {
            st.execute("SELECT pg_advisory_lock(" + PolicyHealthRun.LOCK_SPACE + ", " + PolicyHealthRun.LOCK_UAP + ")");
            try (MockFixture f = MockFixture.start(policies("A", "B", "C", "D"))) {
                long start = System.nanoTime();
                Map<String, Object> blocked = PolicyHealthRun.run(f.policyClient(Api.UAP), db);
                assertEquals("FAILED", blocked.get("status"));
                assertEquals("ALREADY_RUNNING", blocked.get("error_kind"));
                assertEquals(PolicyHealthRun.ALREADY_RUNNING, blocked.get("error"));
                assertTrue((System.nanoTime() - start) / 1_000_000 < 3000, "fails fast, does not wait");
                assertEquals(0, f.mock.requestCount(MockCyberArkServer.POLICIES), "CyberArk not called");

                assertEquals("SUCCESS", PolicyHealthRun.run(f.policyClient(Api.SCA), db).get("status"),
                        "SCA has its own lock");
            }
            st.execute("SELECT pg_advisory_unlock(" + PolicyHealthRun.LOCK_SPACE + ", " + PolicyHealthRun.LOCK_UAP + ")");
        }
        assertEquals("SUCCESS", uap("A", "B", "C", "D").get("status"), "free again once the other session let go");
    }

    @Test
    void realRunsInParallelUapBlocksUapButNotSca() throws Exception {
        try (MockFixture slow = MockFixture.start(policies("A", "B", "C", "D"));
             MockFixture fast = MockFixture.start(policies("A", "B", "C", "D"))) {
            slow.mock.fail(MockCyberArkServer.POLICIES, Fault.DELAY); // the first UAP run takes 2.5 s
            java.util.concurrent.atomic.AtomicReference<Map<String, Object>> first =
                    new java.util.concurrent.atomic.AtomicReference<>();
            Thread runner = new Thread(() -> first.set(PolicyHealthRun.run(slow.policyClient(Api.UAP), db)));
            runner.start();
            waitForLock(PolicyHealthRun.LOCK_UAP);

            Map<String, Object> second = PolicyHealthRun.run(fast.policyClient(Api.UAP), db);
            assertEquals("ALREADY_RUNNING", second.get("error_kind"), String.valueOf(second));
            Map<String, Object> sca = PolicyHealthRun.run(fast.policyClient(Api.SCA), db);
            assertEquals("SUCCESS", sca.get("status"), "SCA runs while UAP runs");

            runner.join(15_000);
            assertEquals("SUCCESS", first.get().get("status"), String.valueOf(first.get()));
        }
    }
}
