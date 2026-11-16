package com.keyforge.cyberarkpoc.rest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyforge.cyberarkpoc.StubHttpServer;
import com.keyforge.cyberarkpoc.client.PvwaClient;
import com.keyforge.cyberarkpoc.client.ResponseBody;
import com.keyforge.cyberarkpoc.config.PvwaConfig;
import com.keyforge.cyberarkpoc.extract.ExtractionSettings;
import com.keyforge.cyberarkpoc.extract.FetchResult;
import com.keyforge.cyberarkpoc.extract.PvwaExtraction;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer.Fault;
import com.keyforge.cyberarkpoc.mock.MockDataset;
import com.keyforge.cyberarkpoc.mock.SampleData;
import com.keyforge.cyberarkpoc.store.DbConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PVWA response-only mode ({@code pvwa/json/<name>}): every extraction returns its records as JSON without a database,
 * against the local mock (made-up data in the documented shapes; this is not a real PVWA test).
 */
class PvwaResponseModeTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final ExtractionSettings FAST = new ExtractionSettings(null, 0, 1000);
    /** Fails the test if the response-only mode ever asks for the database settings. */
    private static final Supplier<DbConfig> NO_DATABASE = () -> {
        throw new AssertionError("response-only mode must not use the database");
    };

    @TempDir
    Path spoolDir;

    private MockCyberArkServer mock;

    @AfterEach
    void stop() {
        if (mock != null) {
            mock.close();
        }
    }

    private ResponseBody.Settings spool() {
        return new ResponseBody.Settings(spoolDir, 1024 * 1024, 0, 0, Duration.ofHours(24));
    }

    private Supplier<PvwaClient> clients(String password) {
        return () -> new PvwaClient(new PvwaConfig(URI.create(mock.rootUrl() + MockCyberArkServer.PVWA_APP),
                "CyberArk", MockCyberArkServer.MOCK_VAULT_USERNAME, password, Duration.ofSeconds(5), null));
    }

    private Map<String, Object> run(String route, ExtractionSettings settings, String password) {
        Map<String, ExtractionRestServer.Route> routes = ExtractionRestServer.pvwaRoutes(NO_DATABASE, settings,
                this::spool);
        return ExtractionRestServer.run(route, routes.get(route), clients(password));
    }

    private Map<String, Object> run(String route) {
        return run(route, FAST, MockCyberArkServer.MOCK_VAULT_PASSWORD);
    }

    /** The whole answer as the REST server would send it, then the temporary file released. */
    private static JsonNode sent(Map<String, Object> result) throws IOException {
        try {
            return MAPPER.readTree(MAPPER.writeValueAsString(result));
        } finally {
            ResponseBody.release(result);
        }
    }

    private long filesLeft() throws IOException {
        try (var files = Files.list(spoolDir)) {
            return files.count();
        }
    }

    @Test
    void everyExtractionReturnsTheSameRecordsAsTheDatabaseModeWithoutADatabase() throws Exception {
        mock = MockCyberArkServer.start(SampleData.demo(), 0);
        Map<String, ExtractionRestServer.Route> routes = ExtractionRestServer.pvwaRoutes(NO_DATABASE, FAST, this::spool);
        List<PvwaExtraction> all = PvwaExtraction.all(FAST);
        assertEquals(8, all.size());

        for (PvwaExtraction extraction : all) {
            String route = extraction.command().replaceFirst("^pvwa-", "pvwa/json/");
            assertTrue(routes.containsKey(route), route);

            FetchResult expected;
            try (PvwaClient client = clients(MockCyberArkServer.MOCK_VAULT_PASSWORD).get()) {
                expected = extraction.fetch().apply(client); // the list the database mode would store
            }
            JsonNode out = sent(run(route));

            String status = !expected.complete() ? "INCOMPLETE"
                    : expected.missingId() > 0 ? "COMPLETED_WITH_FAILURES" : "SUCCESS";
            assertEquals(status, out.get("status").asText(), route + ": " + out);
            assertEquals("response", out.get("mode").asText());
            assertEquals(MAPPER.valueToTree(expected.records()), out.get("records"), route + ": same records, same order");
            assertEquals(expected.records().size(), out.get("records_returned").asInt(), route);
            assertEquals(expected.pages(), out.get("pages").asInt(), route);
            assertEquals(1, out.get("logons").asInt(), route + ": one session per run");
            assertEquals("ok", out.get("logoff").asText(), route + ": logged off");
        }
        assertEquals(0, filesLeft());
    }

    @Test
    void allPagesAreReadAndNoRecordIsRepeated() throws Exception {
        mock = MockCyberArkServer.start(SampleData.demo(), 0);
        JsonNode out = sent(run("pvwa/json/safes", new ExtractionSettings(7, 0, 1000),
                MockCyberArkServer.MOCK_VAULT_PASSWORD));

        assertEquals("SUCCESS", out.get("status").asText(), out.toString());
        assertEquals(30, out.get("records_returned").asInt());
        assertEquals(5, out.get("pages").asInt(), "30 Safes in pages of 7: 7+7+7+7+2");
        java.util.Set<String> ids = new java.util.HashSet<>();
        out.get("records").forEach(r -> ids.add(r.get("safeUrlId").asText()));
        assertEquals(30, ids.size(), "no Safe twice");
        assertEquals(30, out.get("reported_total").asInt());
        assertTrue(out.get("complete").asBoolean());
    }

    @Test
    void pagingThatMakesNoProgressOrAWrongTotalIsIncompleteNeverSuccess() throws Exception {
        mock = MockCyberArkServer.start(SampleData.demo(), 0);
        mock.fail(MockCyberArkServer.PVWA_SAFES, Fault.IGNORE_OFFSET);
        JsonNode stalled = sent(run("pvwa/json/safes"));
        assertEquals("INCOMPLETE", stalled.get("status").asText());
        assertEquals(25, stalled.get("records_returned").asInt(), "the first page only, never repeated");
        assertFalse(stalled.get("complete").asBoolean());
        assertTrue(stalled.get("notes").toString().contains("no progress"), stalled.get("notes").toString());

        mock.clearFaults();
        mock.fail(MockCyberArkServer.PVWA_SAFES, Fault.WRONG_COUNT);
        JsonNode wrongTotal = sent(run("pvwa/json/safes"));
        assertEquals("INCOMPLETE", wrongTotal.get("status").asText());
        assertTrue(wrongTotal.get("notes").toString().contains("reported count 31"), wrongTotal.get("notes").toString());
    }

    @Test
    void anEmptyListIsASuccessWithNoRecords() throws Exception {
        mock = MockCyberArkServer.start(new MockDataset(), 0);
        for (String route : new String[] {"pvwa/json/safes", "pvwa/json/accounts", "pvwa/json/discovered-accounts"}) {
            JsonNode out = sent(run(route));
            assertEquals("SUCCESS", out.get("status").asText(), route + ": " + out);
            assertEquals(0, out.get("records_returned").asInt());
            assertTrue(out.get("records").isArray() && out.get("records").isEmpty(), route);
        }
    }

    @Test
    void secretsAndCredentialsNeverAppearInTheResponse() throws Exception {
        mock = MockCyberArkServer.start(SampleData.demo(), 0);
        Map<String, Object> result = run("pvwa/json/accounts");
        String text = MAPPER.writeValueAsString(result);
        ResponseBody.release(result);

        assertTrue(text.contains("\"records_returned\" : 120") || text.contains("\"records_returned\":120"), text);
        assertFalse(text.contains("MOCK-SECRET-VALUE"), "account secret values removed");
        assertFalse(text.contains("MOCK-NESTED-PASSWORD"), "nested passwords removed");
        assertFalse(text.contains("\"secret\""), "no secret field at all");
        assertFalse(text.contains(MockCyberArkServer.MOCK_VAULT_PASSWORD), "the vault password never appears");
    }

    @Test
    void aRejectedLogonFailsWithNoRecords() throws Exception {
        mock = MockCyberArkServer.start(SampleData.demo(), 0);
        JsonNode out = sent(run("pvwa/json/safes", FAST, "wrong-password"));

        assertEquals("FAILED", out.get("status").asText());
        assertEquals("AUTHENTICATION", out.get("error_kind").asText());
        assertFalse(out.has("records"));
        assertFalse(out.toString().contains("wrong-password"), "the password is never echoed");
        assertEquals(0, mock.requestCount(MockCyberArkServer.PVWA_SAFES), "nothing read without a session");
        assertEquals(0, mock.requestCount(MockCyberArkServer.PVWA_LOGOFF), "no session, nothing to log off");
    }

    @Test
    void theSessionIsLoggedOffAfterSuccessAndAfterFailure() throws Exception {
        mock = MockCyberArkServer.start(SampleData.demo(), 0);
        JsonNode ok = sent(run("pvwa/json/safes"));
        assertEquals("SUCCESS", ok.get("status").asText());
        assertEquals(1, mock.requestCount(MockCyberArkServer.PVWA_LOGOFF));

        mock.fail(MockCyberArkServer.PVWA_ACCOUNTS, Fault.HTTP_500);
        JsonNode failed = sent(run("pvwa/json/accounts"));
        assertEquals("FAILED", failed.get("status").asText());
        assertEquals("HTTP_STATUS", failed.get("error_kind").asText());
        assertEquals(500, failed.get("http_status").asInt());
        assertFalse(failed.has("records"), "no partial records after a failure");
        assertEquals("ok", failed.get("logoff").asText());
        assertEquals(2, mock.requestCount(MockCyberArkServer.PVWA_LOGOFF), "logged off after the failure too");
        assertEquals(0, filesLeft());
    }

    @Test
    void aLargeListGoesThroughATemporaryFileAndIsReturnedWhole() throws Exception {
        int pages = 4;
        int perPage = 1000;
        String app = "/PasswordVault";
        java.util.concurrent.atomic.AtomicInteger calls = new java.util.concurrent.atomic.AtomicInteger();
        try (StubHttpServer stub = new StubHttpServer()
                .reply(app + "/API/auth/Cyberark/Logon/", 200, "\"session-token-123\"")
                .reply(app + "/API/Auth/Logoff/", 200, "")
                .handle(app + "/API/Accounts", ex -> {
                    int page = calls.getAndIncrement();
                    StringBuilder b = new StringBuilder("{\"value\":[");
                    for (int i = 0; i < (page < pages ? perPage : 0); i++) {
                        int n = page * perPage + i;
                        b.append(i == 0 ? "" : ",").append("{\"id\":\"1_").append(n).append("\",\"userName\":\"user")
                                .append(n).append("\",\"secret\":\"S3CR3T\",\"platformAccountProperties\":{\"Note\":\"")
                                .append("x".repeat(300)).append("\"}}");
                    }
                    b.append("],\"count\":").append(pages * perPage).append('}');
                    byte[] bytes = b.toString().getBytes(StandardCharsets.UTF_8);
                    ex.sendResponseHeaders(200, bytes.length);
                    try (OutputStream o = ex.getResponseBody()) {
                        o.write(bytes);
                    }
                })) {
            Map<String, ExtractionRestServer.Route> routes = ExtractionRestServer.pvwaRoutes(NO_DATABASE,
                    new ExtractionSettings(perPage, 0, 1000), this::spool);
            Map<String, Object> result = ExtractionRestServer.run("pvwa/json/accounts", routes.get("pvwa/json/accounts"),
                    () -> new PvwaClient(new PvwaConfig(URI.create(stub.rootUrl() + app), "CyberArk", "svc",
                            "vault-password", Duration.ofSeconds(10), null)));

            ResponseBody records = (ResponseBody) result.get("records");
            assertTrue(records.spooled(), "over 1 MB: kept in a temporary file, not in memory");
            assertEquals(1, filesLeft());
            JsonNode out = sent(result);

            assertEquals("SUCCESS", out.get("status").asText(), out.toString().substring(0, 300));
            assertEquals(pages * perPage, out.get("records_returned").asInt());
            assertEquals(pages * perPage, out.get("records").size());
            assertEquals("1_3999", out.get("records").get(3999).get("id").asText(), "API order kept");
            assertFalse(out.toString().contains("S3CR3T"));
            assertEquals(0, filesLeft(), "the temporary file is deleted once the answer is sent");
        }
    }

    @Test
    void aLocalLimitIsAnExplicitFailureNotATruncatedList() throws Exception {
        mock = MockCyberArkServer.start(SampleData.demo(), 0);
        Map<String, ExtractionRestServer.Route> routes = ExtractionRestServer.pvwaRoutes(NO_DATABASE, FAST,
                () -> new ResponseBody.Settings(spoolDir, 1024, 4096, 0, Duration.ofHours(24)));
        JsonNode out = sent(ExtractionRestServer.run("pvwa/json/accounts", routes.get("pvwa/json/accounts"),
                clients(MockCyberArkServer.MOCK_VAULT_PASSWORD)));

        assertEquals("FAILED", out.get("status").asText());
        assertEquals("LOCAL_LIMIT", out.get("error_kind").asText());
        assertFalse(out.has("records"));
        assertEquals("ok", out.get("logoff").asText());
        assertEquals(0, filesLeft());
    }

    @Test
    void theDatabaseRoutesAreUnchangedAndListedSeparately() {
        Map<String, ExtractionRestServer.Route> routes = ExtractionRestServer.pvwaRoutes(NO_DATABASE, FAST, this::spool);
        List<String> database = new ArrayList<>();
        List<String> json = new ArrayList<>();
        routes.forEach((name, route) -> {
            if (name.startsWith("pvwa/json/")) {
                json.add(name);
                assertTrue(route.description().endsWith("-> JSON response (no database)"), route.description());
            } else if (!name.equals("pvwa/verify")) {
                database.add(name);
                assertTrue(route.description().matches(".* -> pvwa_\\w+$"), route.description());
            }
        });
        assertEquals(8, database.size());
        assertEquals(8, json.size());
    }
}
