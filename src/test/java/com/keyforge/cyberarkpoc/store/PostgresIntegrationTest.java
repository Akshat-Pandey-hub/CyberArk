package com.keyforge.cyberarkpoc.store;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyforge.cyberarkpoc.client.PvwaClient;
import com.keyforge.cyberarkpoc.config.PvwaConfig;
import com.keyforge.cyberarkpoc.extract.ExtractionRunner;
import com.keyforge.cyberarkpoc.extract.ExtractionSettings;
import com.keyforge.cyberarkpoc.extract.PvwaExtraction;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer.Fault;
import com.keyforge.cyberarkpoc.mock.MockDataset;
import com.keyforge.cyberarkpoc.mock.SampleData;
import com.keyforge.cyberarkpoc.rest.ExtractionRestServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Extractions end to end against the local mock and a REAL PostgreSQL, in a throwaway schema that is dropped
 * afterwards. Runs only when {@code CYBERARK_IT_PG_HOST}, {@code CYBERARK_IT_PG_DATABASE},
 * {@code CYBERARK_IT_PG_USERNAME} and {@code CYBERARK_IT_PG_PASSWORD} (optional {@code CYBERARK_IT_PG_PORT})
 * point at a test database; otherwise every test is reported as skipped, never as passed.
 */
class PostgresIntegrationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private MockCyberArkServer mock;
    private DbConfig db;
    private Supplier<PvwaClient> pvwa;

    @BeforeEach
    void setUp() throws Exception {
        Map<String, String> env = System.getenv();
        assumeTrue(env.get("CYBERARK_IT_PG_HOST") != null && env.get("CYBERARK_IT_PG_DATABASE") != null
                        && env.get("CYBERARK_IT_PG_USERNAME") != null && env.get("CYBERARK_IT_PG_PASSWORD") != null,
                "CYBERARK_IT_PG_* not set: PostgreSQL integration tests skipped");
        String port = env.getOrDefault("CYBERARK_IT_PG_PORT", "5432");
        db = new DbConfig(env.get("CYBERARK_IT_PG_HOST"), Integer.parseInt(port), env.get("CYBERARK_IT_PG_DATABASE"),
                env.get("CYBERARK_IT_PG_USERNAME"), env.get("CYBERARK_IT_PG_PASSWORD"),
                "cyberark_it_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12));
        mock = MockCyberArkServer.start(SampleData.demo(), 0);
        PvwaConfig config = new PvwaConfig(URI.create(mock.rootUrl() + MockCyberArkServer.PVWA_APP), "CyberArk",
                MockCyberArkServer.MOCK_VAULT_USERNAME, MockCyberArkServer.MOCK_VAULT_PASSWORD,
                Duration.ofSeconds(5), null);
        pvwa = () -> new PvwaClient(config);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (mock != null) {
            mock.close();
        }
        if (db != null) {
            try (Connection conn = db.open(); Statement st = conn.createStatement()) {
                st.execute("DROP SCHEMA IF EXISTS " + db.schema() + " CASCADE");
            }
        }
    }

    private Map<String, Object> runRoute(String route) {
        Map<String, ExtractionRestServer.Route> routes =
                ExtractionRestServer.pvwaRoutes(() -> db, new ExtractionSettings(null, 0, 1000));
        return ExtractionRestServer.run(route, routes.get(route), pvwa);
    }

    private long count(String sql) throws Exception {
        try (Connection conn = db.open(); Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            rs.next();
            return rs.getLong(1);
        }
    }

    private List<String> columns(String table) throws Exception {
        try (Connection conn = db.open(); Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(
                "SELECT column_name FROM information_schema.columns WHERE table_schema = '" + db.schema()
                        + "' AND table_name = '" + table + "' ORDER BY ordinal_position")) {
            List<String> names = new java.util.ArrayList<>();
            while (rs.next()) {
                names.add(rs.getString(1));
            }
            return names;
        }
    }

    @Test
    void safesAreStoredOneDocumentedFieldPerColumn() throws Exception {
        Map<String, Object> result = runRoute("pvwa/safes");

        assertEquals("SUCCESS", result.get("status"), String.valueOf(result));
        assertEquals(30, result.get("extracted"));
        assertEquals(30, result.get("inserted"));
        List<String> expected = new java.util.ArrayList<>(List.of("record_uuid"));
        PvwaExtraction.SAFE_COLUMNS.forEach(c -> expected.add(c.name()));
        expected.add("extracted_at");
        assertEquals(expected, columns("pvwa_safe"));
        String t = db.schema() + ".pvwa_safe";
        assertEquals(30, count("SELECT count(*) FROM " + t));
        assertEquals(30, count("SELECT count(DISTINCT record_uuid) FROM " + t));
        assertEquals(30, count("SELECT count(*) FROM " + t + " WHERE record_uuid::text ~ "
                + "'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'"), "random (version 4) uuids");
        try (Connection conn = db.open(); Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(
                "SELECT \"safeName\", \"safeNumber\", \"creator\"::text, \"olacEnabled\", \"numberOfVersionsRetention\", "
                        + "\"lastModificationTime\", extracted_at FROM " + t + " WHERE \"safeUrlId\" = 'MOCK-Safe-30'")) {
            assertTrue(rs.next());
            assertEquals("MOCK-Safe-30", rs.getString(1));
            assertEquals(130, rs.getLong(2));
            assertEquals("Administrator", MAPPER.readTree(rs.getString(3)).get("name").asText());
            assertFalse(rs.getBoolean(4));
            rs.getLong(5);
            assertTrue(rs.wasNull(), "null in the response stays NULL");
            assertEquals(1_700_000_000_000_130L, rs.getLong(6), "large microsecond time fits");
            assertTrue(rs.getTimestamp(7) != null);
        }
        assertEquals(List.of("mockTenantSpecificField"), result.get("fields_without_column"),
                "an undocumented field is reported, not silently dropped");
        assertEquals(0, count("SELECT count(*) FROM information_schema.tables WHERE table_schema = '"
                + db.schema() + "' AND table_name <> 'pvwa_safe'"), "no other table is created");
        assertEquals(0, mock.openPvwaSessions(), "logged off");
    }

    @Test
    void rerunUpdatesInPlaceAndKeepsEachUuid() throws Exception {
        runRoute("pvwa/safes");
        String before = uuidOf("MOCK-Safe-01");
        Map<String, Object> second = runRoute("pvwa/safes");

        assertEquals(0, second.get("inserted"));
        assertEquals(30, second.get("updated"));
        assertEquals(30, count("SELECT count(*) FROM " + db.schema() + ".pvwa_safe"));
        assertEquals(before, uuidOf("MOCK-Safe-01"), "the uuid of an existing row never changes");
    }

    private String uuidOf(String cyberarkId) throws Exception {
        try (Connection conn = db.open(); Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(
                "SELECT record_uuid::text FROM " + db.schema() + ".pvwa_safe WHERE \"safeUrlId\" = '" + cyberarkId + "'")) {
            assertTrue(rs.next());
            return rs.getString(1);
        }
    }

    @Test
    void incompleteFetchIsReportedAsIncomplete() {
        mock.fail(MockCyberArkServer.PVWA_SAFES, Fault.WRONG_COUNT);
        Map<String, Object> result = runRoute("pvwa/safes");

        assertEquals("INCOMPLETE", result.get("status"));
        assertTrue(String.valueOf(result.get("notes")).contains("count 31"), String.valueOf(result));
    }

    @Test
    void accountsAreStoredWithoutAnySecretValue() throws Exception {
        Map<String, Object> result = runRoute("pvwa/accounts");

        assertEquals("SUCCESS", result.get("status"), String.valueOf(result));
        assertEquals(120, result.get("inserted"));
        String table = db.schema() + ".pvwa_account";
        assertEquals(120, count("SELECT count(*) FROM " + table));
        assertEquals(0, count("SELECT count(*) FROM " + table + " t WHERE row_to_json(t)::text LIKE '%MOCK-SECRET-VALUE%' "
                + "OR row_to_json(t)::text LIKE '%MOCK-NESTED-PASSWORD%'"), "no secret value stored");
        assertEquals(0, count("SELECT count(*) FROM information_schema.columns WHERE table_schema = '" + db.schema()
                + "' AND table_name = 'pvwa_account' AND lower(column_name) IN ('secret', 'password')"), "no secret column");
        assertEquals(0, count("SELECT count(*) FROM " + table + " WHERE \"platformAccountProperties\" ? 'Password'"),
                "no nested secret stored");
        assertEquals(120, count("SELECT count(*) FROM " + table + " WHERE \"secretType\" = 'password' "
                + "AND \"secretManagement\"->>'status' = 'success' AND \"id\" LIKE '12\\_%'"), "fields mapped");
        assertEquals(List.of(), result.get("fields_without_column"), "every account field has a column");
        assertFalse(MAPPER.writeValueAsString(result).contains("MOCK-SECRET-VALUE"), "REST body has no secret");
    }

    @Test
    void safeMembersAreStoredPerSafeAndMemberAndReRunsUpdateInPlace() throws Exception {
        Map<String, Object> first = runRoute("pvwa/safe-members");

        assertEquals("SUCCESS", first.get("status"), String.valueOf(first));
        assertEquals(88, first.get("inserted"));
        String t = db.schema() + ".pvwa_safe_member";
        List<String> expected = new java.util.ArrayList<>(List.of("record_uuid"));
        PvwaExtraction.SAFE_MEMBER_COLUMNS.forEach(c -> expected.add(c.name()));
        expected.add("extracted_at");
        assertEquals(expected, columns("pvwa_safe_member"));
        assertEquals(1, count("SELECT count(*) FROM pg_constraint WHERE conrelid = '" + t + "'::regclass "
                + "AND pg_get_constraintdef(oid) = 'UNIQUE (\"safeUrlId\", \"memberId\")'"), "two-part unique key");
        assertEquals(30, count("SELECT count(*) FROM " + t + " WHERE \"memberId\" = 1"), "one row per Safe");
        assertEquals(88, count("SELECT count(*) FROM " + t + " WHERE \"membershipExpirationDate\" IS NULL "
                + "AND \"isReadOnly\" AND NOT \"isPredefinedUser\" AND \"permissions\"->>'listAccounts' = 'true' "
                + "AND \"permissions\"->>'retrieveAccounts' = 'false'"), "fields mapped, nulls kept as NULL");
        try (Connection conn = db.open(); Statement st = conn.createStatement()) {
            st.execute("CREATE TABLE " + db.schema() + ".snap AS SELECT \"safeUrlId\", \"memberId\", record_uuid FROM " + t);
        }

        Map<String, Object> second = runRoute("pvwa/safe-members");

        assertEquals(0, second.get("inserted"));
        assertEquals(88, second.get("updated"));
        assertEquals(88, count("SELECT count(*) FROM " + t));
        assertEquals(0, count("SELECT count(*) FROM " + t + " m JOIN " + db.schema() + ".snap s USING (\"safeUrlId\", "
                + "\"memberId\") WHERE m.record_uuid <> s.record_uuid"), "uuids unchanged");
    }

    @Test
    void targetPlatformsAreStoredOneFieldPerColumnAndReRunsUpdateInPlace() throws Exception {
        Map<String, Object> first = runRoute("pvwa/target-platforms");

        assertEquals("SUCCESS", first.get("status"), String.valueOf(first));
        assertEquals(3, first.get("inserted"));
        assertEquals(List.of(), first.get("fields_without_column"));
        String t = db.schema() + ".pvwa_target_platform";
        List<String> expected = new java.util.ArrayList<>(List.of("record_uuid"));
        PvwaExtraction.TARGET_PLATFORM_COLUMNS.forEach(c -> expected.add(c.name()));
        expected.add("extracted_at");
        assertEquals(expected, columns("pvwa_target_platform"));
        assertEquals(1, count("SELECT count(*) FROM pg_constraint WHERE conrelid = '" + t + "'::regclass "
                + "AND pg_get_constraintdef(oid) = 'UNIQUE (\"PlatformID\")'"));
        assertEquals(1, count("SELECT count(*) FROM " + t + " WHERE \"PlatformID\" = 'WinServerLocal' AND \"ID\" = 11 "
                + "AND \"Active\" AND \"CredentialsManagementPolicy\"->'Change'->>'RequirePasswordEveryXDays' = '30' "
                + "AND \"PrivilegedSessionManagement\"->>'PSMServerId' = ''"), "fields and nested policy mapped");
        assertEquals(1, count("SELECT count(*) FROM " + t + " WHERE NOT \"Active\""), "inactive platform kept");
        String uuid;
        try (Connection conn = db.open(); Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(
                "SELECT record_uuid::text FROM " + t + " WHERE \"PlatformID\" = 'UnixSSH'")) {
            rs.next();
            uuid = rs.getString(1);
        }

        Map<String, Object> second = runRoute("pvwa/target-platforms");

        assertEquals(0, second.get("inserted"));
        assertEquals(3, second.get("updated"));
        assertEquals(3, count("SELECT count(*) FROM " + t));
        assertEquals(1, count("SELECT count(*) FROM " + t + " WHERE record_uuid::text = '" + uuid + "'"), "uuid kept");
    }

    @Test
    void platformDetailsAreStoredPerPlatformWithNullsKeptAndReRunsUpdateInPlace() throws Exception {
        MockDataset data = SampleData.demo()
                .targetPlatform(30, "NoActiveFlag", "Platform without Active", "Windows", true, 30)
                .platformDetailsBody("NoActiveFlag", "{\"PlatformID\": \"NoActiveFlag\", \"Properties\": null}");
        try (MockCyberArkServer other = MockCyberArkServer.start(data, 0)) {
            PvwaConfig config = new PvwaConfig(URI.create(other.rootUrl() + MockCyberArkServer.PVWA_APP), "CyberArk",
                    MockCyberArkServer.MOCK_VAULT_USERNAME, MockCyberArkServer.MOCK_VAULT_PASSWORD,
                    Duration.ofSeconds(5), null);
            Map<String, ExtractionRestServer.Route> routes =
                    ExtractionRestServer.pvwaRoutes(() -> db, new ExtractionSettings(null, 0, 1000));
            Supplier<Map<String, Object>> run = () -> ExtractionRestServer.run("pvwa/platform-details",
                    routes.get("pvwa/platform-details"), () -> new PvwaClient(config));

            Map<String, Object> first = run.get();

            assertEquals("SUCCESS", first.get("status"), String.valueOf(first));
            assertEquals(4, first.get("inserted"));
            assertEquals(List.of(), first.get("fields_without_column"));
            String t = db.schema() + ".pvwa_platform_detail";
            assertEquals(List.of("record_uuid", "PlatformID", "Properties", "Active", "extracted_at"),
                    columns("pvwa_platform_detail"));
            assertEquals(1, count("SELECT count(*) FROM pg_constraint WHERE conrelid = '" + t + "'::regclass "
                    + "AND pg_get_constraintdef(oid) = 'UNIQUE (\"PlatformID\")'"));
            assertEquals(1, count("SELECT count(*) FROM " + t + " WHERE \"PlatformID\" = 'WinServerLocal' AND \"Active\" "
                    + "AND \"Properties\"->>'RequirePasswordChangeEveryXDays' = '30'"), "Properties kept as jsonb");
            assertEquals(1, count("SELECT count(*) FROM " + t + " WHERE \"PlatformID\" = 'UnixSSH' AND NOT \"Active\""));
            assertEquals(1, count("SELECT count(*) FROM " + t + " WHERE \"PlatformID\" = 'NoActiveFlag' "
                    + "AND \"Active\" IS NULL AND \"Properties\" IS NULL"), "absent and null values stored as NULL");
            try (Connection conn = db.open(); Statement st = conn.createStatement()) {
                st.execute("CREATE TABLE " + db.schema() + ".snap_pd AS SELECT \"PlatformID\", record_uuid FROM " + t);
            }

            Map<String, Object> second = run.get();

            assertEquals(0, second.get("inserted"));
            assertEquals(4, second.get("updated"));
            assertEquals(4, count("SELECT count(*) FROM " + t));
            assertEquals(0, count("SELECT count(*) FROM " + t + " d JOIN " + db.schema() + ".snap_pd s "
                    + "USING (\"PlatformID\") WHERE d.record_uuid <> s.record_uuid"), "uuids unchanged");
        }
    }

    @Test
    void usersAreStoredOneFieldPerColumnAndReRunsUpdateInPlace() throws Exception {
        Map<String, Object> first = runRoute("pvwa/users");

        assertEquals("SUCCESS", first.get("status"), String.valueOf(first));
        assertEquals(30, first.get("inserted"));
        assertEquals(List.of(), first.get("fields_without_column"));
        String t = db.schema() + ".pvwa_user";
        List<String> expected = new java.util.ArrayList<>(List.of("record_uuid"));
        PvwaExtraction.USER_COLUMNS.forEach(c -> expected.add(c.name()));
        expected.add("extracted_at");
        assertEquals(expected, columns("pvwa_user"));
        assertEquals(1, count("SELECT count(*) FROM pg_constraint WHERE conrelid = '" + t + "'::regclass "
                + "AND pg_get_constraintdef(oid) = 'UNIQUE (id)'"));
        assertEquals(1, count("SELECT count(*) FROM " + t + " WHERE \"id\" = 2 AND \"username\" = 'Administrator' "
                + "AND \"userDN\" IS NULL AND \"enabled\" AND NOT \"suspended\" AND NOT \"componentUser\" "
                + "AND \"groupsMembership\" @> '[{\"groupName\": \"Vault Admins\"}]' "
                + "AND \"vaultAuthorization\" ? 'AuditUsers' AND \"personalDetails\"->>'organization' = 'MOCK Org'"),
                "fields mapped, lists and objects as jsonb, an absent userDN stored as NULL");
        assertEquals(1, count("SELECT count(*) FROM " + t + " WHERE \"suspended\""));
        assertEquals(1, count("SELECT count(*) FROM " + t + " WHERE NOT \"enabled\""));
        assertEquals(1, count("SELECT count(*) FROM " + t + " WHERE \"userDN\" LIKE 'CN=mock.ldap.user,%'"));
        try (Connection conn = db.open(); Statement st = conn.createStatement()) {
            st.execute("CREATE TABLE " + db.schema() + ".snap_u AS SELECT \"id\", record_uuid FROM " + t);
        }

        Map<String, Object> second = runRoute("pvwa/users");

        assertEquals(0, second.get("inserted"));
        assertEquals(30, second.get("updated"));
        assertEquals(30, count("SELECT count(*) FROM " + t));
        assertEquals(0, count("SELECT count(*) FROM " + t + " u JOIN " + db.schema() + ".snap_u s USING (\"id\") "
                + "WHERE u.record_uuid <> s.record_uuid"), "uuids unchanged");
    }

    @Test
    void userGroupsAreStoredOneFieldPerColumnAndReRunsUpdateInPlace() throws Exception {
        Map<String, Object> first = runRoute("pvwa/user-groups");

        assertEquals("SUCCESS", first.get("status"), String.valueOf(first));
        assertEquals(30, first.get("inserted"));
        assertEquals(List.of(), first.get("fields_without_column"));
        String t = db.schema() + ".pvwa_user_group";
        List<String> expected = new java.util.ArrayList<>(List.of("record_uuid"));
        PvwaExtraction.USER_GROUP_COLUMNS.forEach(c -> expected.add(c.name()));
        expected.add("extracted_at");
        assertEquals(expected, columns("pvwa_user_group"));
        assertEquals(1, count("SELECT count(*) FROM pg_constraint WHERE conrelid = '" + t + "'::regclass "
                + "AND pg_get_constraintdef(oid) = 'UNIQUE (id)'"));
        assertEquals(1, count("SELECT count(*) FROM " + t + " WHERE \"id\" = 11 AND \"groupName\" = 'Vault Admins' "
                + "AND \"groupType\" = 'Vault' AND \"dn\" IS NULL AND \"directory\" IS NULL "
                + "AND \"members\" @> '[{\"username\": \"Administrator\", \"id\": 2}]'"),
                "fields mapped, members as jsonb, absent Directory-only fields stored as NULL");
        assertEquals(1, count("SELECT count(*) FROM " + t + " WHERE \"groupType\" = 'Directory' "
                + "AND \"dn\" LIKE 'CN=MOCK LDAP Readers,%' AND \"directory\" = 'mock.example.test'"));
        assertEquals(1, count("SELECT count(*) FROM " + t + " WHERE \"members\" = '[]'::jsonb"), "empty group kept");
        try (Connection conn = db.open(); Statement st = conn.createStatement()) {
            st.execute("CREATE TABLE " + db.schema() + ".snap_g AS SELECT \"id\", record_uuid FROM " + t);
        }

        Map<String, Object> second = runRoute("pvwa/user-groups");

        assertEquals(0, second.get("inserted"));
        assertEquals(30, second.get("updated"));
        assertEquals(30, count("SELECT count(*) FROM " + t));
        assertEquals(0, count("SELECT count(*) FROM " + t + " g JOIN " + db.schema() + ".snap_g s USING (\"id\") "
                + "WHERE g.record_uuid <> s.record_uuid"), "uuids unchanged");
    }

    @Test
    void discoveredAccountsAreStoredWithBothDocumentedDateNamesAndTheScopeNote() throws Exception {
        Map<String, Object> first = runRoute("pvwa/discovered-accounts");

        assertEquals("SUCCESS", first.get("status"), String.valueOf(first));
        assertEquals(130, first.get("inserted"));
        assertEquals(List.of(), first.get("fields_without_column"));
        assertTrue(String.valueOf(first.get("notes")).contains("not proof that it does not exist"),
                "the scope note reaches the REST response");
        String t = db.schema() + ".pvwa_discovered_account";
        List<String> expected = new java.util.ArrayList<>(List.of("record_uuid"));
        PvwaExtraction.DISCOVERED_ACCOUNT_COLUMNS.forEach(c -> expected.add(c.name()));
        expected.add("extracted_at");
        assertEquals(expected, columns("pvwa_discovered_account"));
        assertEquals(1, count("SELECT count(*) FROM pg_constraint WHERE conrelid = '" + t + "'::regclass "
                + "AND pg_get_constraintdef(oid) = 'UNIQUE (id)'"));
        assertEquals(14, count("SELECT count(*) FROM " + t + " WHERE \"privileged\""), "12 Windows admins + AWS + Unix");
        assertEquals(1, count("SELECT count(*) FROM " + t + " WHERE \"id\" = '18_901' AND \"discoveryDate\" = 1700000800 "
                + "AND \"discoveryDateTime\" IS NULL AND \"osVersion\" IS NULL "
                + "AND \"platformTypeAccountProperties\"->>'awsAccountID' = '123456789012'"),
                "the example's discoveryDate kept, omitted properties stored as NULL");
        assertEquals(1, count("SELECT count(*) FROM " + t + " WHERE \"id\" = '18_902' AND \"discoveryDateTime\" = 1700000900 "
                + "AND \"discoveryDate\" IS NULL AND (\"platformTypeAccountProperties\"->>'uid')::int = 0"));
        assertEquals(1, count("SELECT count(*) FROM " + t + " WHERE \"id\" = '18_10' AND \"userName\" = 'administrator' "
                + "AND \"lastPasswordSetDateTime\" = 1700000700 AND \"numberOfDependencies\" = 2 "
                + "AND \"additionalProperties\"->>'AccountType' = 'Local'"));
        try (Connection conn = db.open(); Statement st = conn.createStatement()) {
            st.execute("CREATE TABLE " + db.schema() + ".snap_d AS SELECT \"id\", record_uuid FROM " + t);
        }

        Map<String, Object> second = runRoute("pvwa/discovered-accounts");

        assertEquals(0, second.get("inserted"));
        assertEquals(130, second.get("updated"));
        assertEquals(130, count("SELECT count(*) FROM " + t));
        assertEquals(0, count("SELECT count(*) FROM " + t + " d JOIN " + db.schema() + ".snap_d s USING (\"id\") "
                + "WHERE d.record_uuid <> s.record_uuid"), "uuids unchanged");
    }

    @Test
    void aMemberWithAWrongTypeFailsAloneAndIsReported() throws Exception {
        MockDataset data = new MockDataset().safe("S1", "S1", 1)
                .safeMember("S1", "S1", 1, 5, "good", "User")
                .safeMember("S1", "S1", 1, 6, "bad", "User")
                .withSafeMemberField("S1", "isReadOnly", "not-a-boolean");
        try (MockCyberArkServer other = MockCyberArkServer.start(data, 0)) {
            PvwaConfig config = new PvwaConfig(URI.create(other.rootUrl() + MockCyberArkServer.PVWA_APP), "CyberArk",
                    MockCyberArkServer.MOCK_VAULT_USERNAME, MockCyberArkServer.MOCK_VAULT_PASSWORD,
                    Duration.ofSeconds(5), null);
            Map<String, ExtractionRestServer.Route> routes =
                    ExtractionRestServer.pvwaRoutes(() -> db, new ExtractionSettings(null, 0, 1000));
            Map<String, Object> result = ExtractionRestServer.run("pvwa/safe-members",
                    routes.get("pvwa/safe-members"), () -> new PvwaClient(config));

            assertEquals("COMPLETED_WITH_FAILURES", result.get("status"), String.valueOf(result));
            assertEquals(1, result.get("inserted"));
            assertEquals(1, result.get("failed"));
            assertTrue(String.valueOf(result.get("error")).contains("isReadOnly is not true/false"));
            assertEquals(1, count("SELECT count(*) FROM " + db.schema() + ".pvwa_safe_member WHERE \"memberName\" = 'good'"));
        }
    }

    @Test
    void unexpectedErrorIsReportedAndTheSessionIsClosed() throws Exception {
        PvwaExtraction broken = new PvwaExtraction("pvwa-broken", "pvwa_broken", "id",
                List.of(com.keyforge.cyberarkpoc.store.Column.text("id")), "throws after logon",
                client -> {
                    client.verify();
                    throw new IllegalStateException("simulated bug with password=" + MockCyberArkServer.MOCK_VAULT_PASSWORD);
                });
        Map<String, Object> result;
        try (PvwaClient client = pvwa.get()) {
            result = ExtractionRunner.run(broken, client, db);
        }

        assertEquals("FAILED", result.get("status"));
        assertEquals("INTERNAL", result.get("error_kind"));
        assertTrue(String.valueOf(result.get("error")).contains("IllegalStateException"));
        assertFalse(String.valueOf(result.get("error")).contains(MockCyberArkServer.MOCK_VAULT_PASSWORD));
        assertEquals(0, count("SELECT count(*) FROM " + db.schema() + ".pvwa_broken"));
        assertEquals(0, mock.openPvwaSessions(), "logged off");
    }

    @Test
    void secretsInAnErrorBodyNeverReachTheResponse() throws Exception {
        mock.fail(MockCyberArkServer.PVWA_ACCOUNTS, Fault.ERROR_WITH_SECRET);
        Map<String, Object> result = runRoute("pvwa/accounts");

        assertEquals("FAILED", result.get("status"));
        for (String secret : MockCyberArkServer.ERROR_BODY_SECRETS) {
            assertFalse(MAPPER.writeValueAsString(result).contains(secret), secret + " in the REST body");
        }
        assertEquals(0, count("SELECT count(*) FROM " + db.schema() + ".pvwa_account"));
    }

    @Test
    void failedCallIsReportedAsFailedAndStoresNothing() throws Exception {
        mock.fail(MockCyberArkServer.PVWA_SAFES, Fault.HTTP_403);
        Map<String, Object> result = runRoute("pvwa/safes");

        assertEquals("FAILED", result.get("status"));
        assertEquals("AUTHENTICATION", result.get("error_kind"));
        assertEquals(0, count("SELECT count(*) FROM " + db.schema() + ".pvwa_safe"));
        assertEquals(0, mock.openPvwaSessions(), "logged off even after failing");
    }
}
