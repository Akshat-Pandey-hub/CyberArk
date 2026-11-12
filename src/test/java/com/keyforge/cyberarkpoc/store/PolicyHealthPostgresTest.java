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
                    + "' AND tablename = 'uap_policy' AND indexdef LIKE 'CREATE UNIQUE INDEX%(policy_id)'"));
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
}
