package com.keyforge.cyberarkpoc.store;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyforge.cyberarkpoc.StubHttpServer;
import com.keyforge.cyberarkpoc.client.PvwaClient;
import com.keyforge.cyberarkpoc.config.PvwaConfig;
import com.keyforge.cyberarkpoc.extract.ExtractionRunner;
import com.keyforge.cyberarkpoc.extract.ExtractionSettings;
import com.keyforge.cyberarkpoc.extract.PvwaExtraction;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The generic store against a REAL PostgreSQL (throwaway schema): fields come from the records received, nothing is
 * dropped or renamed, types widen instead of failing. Runs only when {@code CYBERARK_IT_PG_*} point at a test
 * database; otherwise every test is reported as skipped. Fixtures and stubs are not proof of a live tenant.
 */
class GenericStorePostgresTest {

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
                "cyberark_gen_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12));
    }

    @AfterEach
    void tearDown() throws Exception {
        if (db != null) {
            try (Connection conn = db.open(); Statement st = conn.createStatement()) {
                st.execute("DROP SCHEMA IF EXISTS " + db.schema() + " CASCADE");
            }
        }
    }

    private static List<JsonNode> json(String... records) throws Exception {
        List<JsonNode> list = new ArrayList<>();
        for (String r : records) {
            list.add(MAPPER.readTree(r));
        }
        return list;
    }

    /** Stores the records in table {@code t} keyed by {@code id}, as one run, and returns the schema changes. */
    private GenericRecordStore.Prepared store(List<JsonNode> records) throws Exception {
        GenericRecordStore store = new GenericRecordStore(db.schema(), "t", List.of("id"));
        try (Connection conn = db.open()) {
            store.ensureTable(conn);
            GenericRecordStore.Prepared p = store.prepare(conn, records);
            for (JsonNode r : records) {
                store.upsert(conn, p, r);
            }
            return p;
        }
    }

    private Map<String, String> types(String table) throws Exception {
        Map<String, String> types = new LinkedHashMap<>();
        try (Connection conn = db.open(); Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(
                "SELECT column_name, data_type FROM information_schema.columns WHERE table_schema = '" + db.schema()
                        + "' AND table_name = '" + table + "' ORDER BY ordinal_position")) {
            while (rs.next()) {
                types.put(rs.getString(1), rs.getString(2));
            }
        }
        return types;
    }

    private String value(String sql) throws Exception {
        try (Connection conn = db.open(); Statement st = conn.createStatement(); ResultSet rs = st.executeQuery(sql)) {
            return rs.next() ? rs.getString(1) : "<no row>";
        }
    }

    private static String fixture(String name) throws Exception {
        try (InputStream in = GenericStorePostgresTest.class.getResourceAsStream("/official/" + name)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private Map<String, Object> runAgainstStub(PvwaExtraction extraction, String path, String body) throws Exception {
        try (StubHttpServer stub = new StubHttpServer()
                .reply("/PasswordVault/API/auth/Cyberark/Logon/", 200, "\"stub-token\"")
                .reply("/PasswordVault/API/Auth/Logoff/", 200, "{}")
                .reply(path, 200, body);
             PvwaClient client = new PvwaClient(new PvwaConfig(URI.create(stub.rootUrl() + "/PasswordVault"),
                     "CyberArk", "u", "p", Duration.ofSeconds(5), null))) {
            return ExtractionRunner.run(extraction, client, db);
        }
    }

    @Test
    void theOfficialSafesExampleIsStoredFieldByFieldUnderItsExactNames() throws Exception {
        Map<String, Object> result = runAgainstStub(PvwaExtraction.safes(ExtractionSettings.defaults()),
                "/PasswordVault/API/Safes/", fixture("pvwa-safes.official-derived.json"));

        assertEquals("SUCCESS", result.get("status"), String.valueOf(result));
        Map<String, String> types = types("pvwa_safe");
        assertEquals(List.of("record_uuid", "extracted_at", "safeUrlId", "safeName", "safeNumber", "description",
                "location", "creator", "olacEnabled", "managingCPM", "numberOfVersionsRetention",
                "numberOfDaysRetention", "autoPurgeEnabled", "creationTime", "lastModificationTime", "isExpiredMember"),
                List.copyOf(types.keySet()));
        assertEquals("bigint", types.get("safeNumber"));
        assertEquals("boolean", types.get("olacEnabled"));
        assertEquals("jsonb", types.get("creator"));
        assertEquals("text", types.get("numberOfVersionsRetention"), "only null seen so far");
        String t = db.schema() + ".pvwa_safe";
        assertEquals("1610319618268452", value("SELECT \"lastModificationTime\" FROM " + t));
        assertEquals("\\", value("SELECT location FROM " + t));
        assertEquals("Administrator", value("SELECT creator->>'name' FROM " + t));
    }

    @Test
    void theOfficialAccountsExampleIsStoredWithoutItsSecret() throws Exception {
        Map<String, Object> result = runAgainstStub(PvwaExtraction.accounts(ExtractionSettings.defaults()),
                "/PasswordVault/API/Accounts", fixture("pvwa-accounts.official-derived.json"));

        assertEquals("SUCCESS", result.get("status"), String.valueOf(result));
        Map<String, String> types = types("pvwa_account");
        assertFalse(types.containsKey("secret"), "the documented secret field never becomes a column");
        assertEquals("jsonb", types.get("secretManagement"));
        assertEquals("inProcess", value("SELECT \"secretManagement\"->>'status' FROM " + db.schema() + ".pvwa_account"));
    }

    @Test
    void additionalFieldsAndDifferentCasingAreStoredAsTheyCome() throws Exception {
        store(json("{\"id\": \"1\", \"Name\": \"upper\", \"tenantOnly\": \"x\"}",
                "{\"id\": \"2\", \"name\": \"lower\"}"));

        Map<String, String> types = types("t");
        assertTrue(types.containsKey("Name") && types.containsKey("name"), "case kept: two different columns");
        assertEquals("x", value("SELECT \"tenantOnly\" FROM " + db.schema() + ".t WHERE id = '1'"));
        assertEquals("lower", value("SELECT name FROM " + db.schema() + ".t WHERE id = '2'"));
        assertNull(value("SELECT \"Name\" FROM " + db.schema() + ".t WHERE id = '2'"));
    }

    @Test
    void nestedObjectsAndArraysAtSeveralLevelsAreKeptExactly() throws Exception {
        String nested = "{\"a\": {\"b\": {\"c\": [1, {\"d\": true, \"e\": null}, [\"x\"]]}}, \"f\": []}";
        store(json("{\"id\": \"1\", \"deep\": " + nested + "}"));

        JsonNode stored = MAPPER.readTree(value("SELECT deep::text FROM " + db.schema() + ".t"));
        assertEquals(MAPPER.readTree(nested), stored);
        assertEquals("jsonb", types("t").get("deep"));
    }

    @Test
    void scalarTypesAreKeptAndATextNumberStaysText() throws Exception {
        store(json("{\"id\": \"1\", \"b\": true, \"i\": 42, \"big\": 1700000000000000101, \"d\": 1.25, "
                + "\"s\": \"hello\", \"numericText\": \"123\"}"));

        Map<String, String> types = types("t");
        assertEquals("boolean", types.get("b"));
        assertEquals("bigint", types.get("i"));
        assertEquals("bigint", types.get("big"));
        assertEquals("numeric", types.get("d"));
        assertEquals("text", types.get("s"));
        assertEquals("text", types.get("numericText"), "never coerced into a number");
        assertEquals("1.25", value("SELECT d FROM " + db.schema() + ".t"));
    }

    @Test
    void missingFieldsAndExplicitNullsAreNullAndANullOnlyColumnTakesItsFirstRealType() throws Exception {
        store(json("{\"id\": \"1\", \"x\": null}", "{\"id\": \"2\"}"));
        assertEquals("text", types("t").get("x"), "only null seen: created as text");
        assertEquals("0", value("SELECT count(*) FROM " + db.schema() + ".t WHERE x IS NOT NULL"));

        GenericRecordStore.Prepared second = store(json("{\"id\": \"3\", \"x\": 5}"));
        assertEquals("bigint", types("t").get("x"), "no value yet, so the real type is taken, not text");
        assertTrue(second.changes().contains("widened \"x\" text -> bigint"), second.changes().toString());
    }

    @Test
    void conflictingTypesWidenTheColumnWithinARunAndAcrossRunsWithoutLosingValues() throws Exception {
        store(json("{\"id\": \"1\", \"mixed\": 1}", "{\"id\": \"2\", \"mixed\": \"two\"}"));
        assertEquals("text", types("t").get("mixed"));
        assertEquals("1", value("SELECT mixed FROM " + db.schema() + ".t WHERE id = '1'"));

        store(json("{\"id\": \"10\", \"n\": 1}"));
        assertEquals("bigint", types("t").get("n"));
        store(json("{\"id\": \"11\", \"n\": 2.5}"));
        assertEquals("numeric", types("t").get("n"));
        store(json("{\"id\": \"12\", \"n\": {\"v\": 3}}"));
        assertEquals("jsonb", types("t").get("n"));
        assertEquals("1", value("SELECT n::text FROM " + db.schema() + ".t WHERE id = '10'"), "the old value survives");
        assertEquals("2.5", value("SELECT n::text FROM " + db.schema() + ".t WHERE id = '11'"));
        assertEquals("{\"v\": 3}", value("SELECT n::text FROM " + db.schema() + ".t WHERE id = '12'"));
    }

    @Test
    void reRunsUpdateInPlaceKeepTheUuidAndClearAFieldThatDisappeared() throws Exception {
        store(json("{\"id\": \"1\", \"x\": 1, \"y\": \"a\"}"));
        String uuid = value("SELECT record_uuid::text FROM " + db.schema() + ".t");

        store(json("{\"id\": \"1\", \"y\": \"b\"}"));

        assertEquals("1", value("SELECT count(*) FROM " + db.schema() + ".t"));
        assertEquals(uuid, value("SELECT record_uuid::text FROM " + db.schema() + ".t"));
        assertNull(value("SELECT x::text FROM " + db.schema() + ".t"), "not left stale");
        assertEquals("b", value("SELECT y FROM " + db.schema() + ".t"));
    }

    @Test
    void namesThatCannotBeColumnsAreKeptInExtraFields() throws Exception {
        String longName = "x".repeat(70);
        store(json("{\"id\": \"1\", \"record_uuid\": \"theirs\", \"" + longName + "\": 7}"));

        JsonNode extra = MAPPER.readTree(value("SELECT _extra_fields::text FROM " + db.schema() + ".t"));
        assertEquals("theirs", extra.get("record_uuid").asText());
        assertEquals(7, extra.get(longName).asInt());
    }

    @Test
    void anEmptyResponseCreatesOnlyTheServiceColumnsAndARecordWithoutItsIdIsRefused() throws Exception {
        store(List.of());
        assertTrue(types("t").keySet().containsAll(List.of("record_uuid", "extracted_at", "id")));

        GenericRecordStore store = new GenericRecordStore(db.schema(), "t", List.of("id"));
        try (Connection conn = db.open()) {
            GenericRecordStore.Prepared p = store.prepare(conn, json("{\"x\": 1}"));
            assertThrows(IllegalArgumentException.class, () -> store.upsert(conn, p, MAPPER.readTree("{\"x\": 1}")));
        }
    }

    @Test
    void concurrentRunsAddingDifferentColumnsDoNotCollide() throws Exception {
        GenericRecordStore store = new GenericRecordStore(db.schema(), "t", List.of("id"));
        try (Connection conn = db.open()) {
            store.ensureTable(conn);
        }
        ExecutorService pool = Executors.newFixedThreadPool(4);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> runs = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            int n = i;
            runs.add(pool.submit(() -> {
                start.await();
                try (Connection conn = db.open()) {
                    List<JsonNode> records = json("{\"id\": \"" + n + "\", \"field" + n + "\": " + n + ", \"shared\": 1}");
                    GenericRecordStore.Prepared p = store.prepare(conn, records);
                    store.upsert(conn, p, records.get(0));
                }
                return null;
            }));
        }
        start.countDown();
        for (Future<?> f : runs) {
            f.get();
        }
        pool.shutdown();
        Map<String, String> types = types("t");
        for (int i = 0; i < 4; i++) {
            assertEquals("bigint", types.get("field" + i));
        }
        assertEquals("4", value("SELECT count(*) FROM " + db.schema() + ".t"));
    }

    @Test
    void aFailedSchemaChangeLeavesTheTableAsItWasAndTheNextRunRecovers() throws Exception {
        store(json("{\"id\": \"1\", \"x\": 1}"));
        GenericRecordStore store = new GenericRecordStore(db.schema(), "t", List.of("id"));
        Connection broken = db.open();
        broken.close();
        assertThrows(SQLException.class, () -> store.prepare(broken, json("{\"id\": \"2\", \"newField\": 1}")));
        assertFalse(types("t").containsKey("newField"));

        store(json("{\"id\": \"2\", \"newField\": 1}"));
        assertEquals("bigint", types("t").get("newField"));
    }

    @Test
    void aTimeoutIsAFailedRunThatStoresNothing() throws Exception {
        try (ServerSocket silent = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            Thread acceptor = new Thread(() -> {
                try {
                    Socket s = silent.accept();
                    Thread.sleep(10_000); // accepts the connection but never answers
                    s.close();
                } catch (Exception ignored) {
                    // the test is over
                }
            });
            acceptor.setDaemon(true);
            acceptor.start();
            try (PvwaClient client = new PvwaClient(new PvwaConfig(
                    URI.create("http://127.0.0.1:" + silent.getLocalPort() + "/PasswordVault"), "CyberArk",
                    MockCyberArkServer.MOCK_VAULT_USERNAME, MockCyberArkServer.MOCK_VAULT_PASSWORD,
                    Duration.ofSeconds(1), null))) {
                Map<String, Object> result = ExtractionRunner.run(PvwaExtraction.safes(ExtractionSettings.defaults()),
                        client, db);

                assertEquals("FAILED", result.get("status"));
                assertEquals("TRANSPORT", result.get("error_kind"));
                assertFalse(String.valueOf(result).contains(MockCyberArkServer.MOCK_VAULT_PASSWORD));
            }
        }
        assertEquals("0", value("SELECT count(*) FROM " + db.schema() + ".pvwa_safe"));
    }
}
