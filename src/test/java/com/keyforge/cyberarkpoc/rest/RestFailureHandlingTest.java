package com.keyforge.cyberarkpoc.rest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyforge.cyberarkpoc.client.PvwaClient;
import com.keyforge.cyberarkpoc.config.PvwaConfig;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer.Fault;
import com.keyforge.cyberarkpoc.mock.SampleData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** D1/D2 regressions: unexpected errors still answer JSON, sessions are closed, and nothing secret leaks. */
class RestFailureHandlingTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private MockCyberArkServer mock;
    private ExtractionRestServer rest;
    private final ByteArrayOutputStream console = new ByteArrayOutputStream();
    private PrintStream out;
    private PrintStream err;

    @BeforeEach
    void captureConsole() throws Exception {
        out = System.out;
        err = System.err;
        PrintStream capture = new PrintStream(console, true, StandardCharsets.UTF_8);
        System.setOut(capture);
        System.setErr(capture);
        mock = MockCyberArkServer.start(SampleData.demo(), 0);
    }

    @AfterEach
    void restore() {
        System.setOut(out);
        System.setErr(err);
        if (rest != null) {
            rest.stop();
        }
        mock.close();
    }

    private Supplier<PvwaClient> vault() {
        PvwaConfig config = new PvwaConfig(URI.create(mock.rootUrl() + MockCyberArkServer.PVWA_APP), "CyberArk",
                MockCyberArkServer.MOCK_VAULT_USERNAME, MockCyberArkServer.MOCK_VAULT_PASSWORD, Duration.ofSeconds(5),
                null);
        return () -> new PvwaClient(config);
    }

    private void start(Supplier<PvwaClient> pvwa, Map<String, ExtractionRestServer.Route> routes) throws Exception {
        rest = new ExtractionRestServer(new ExtractionRestServer.Settings("127.0.0.1", 0, "u", "p"), pvwa, routes);
        rest.start();
    }

    private HttpResponse<String> get(String route) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + rest.port()
                        + ExtractionRestServer.BASE_PATH + "/" + route))
                .header("Authorization", "Basic " + Base64.getEncoder().encodeToString("u:p".getBytes()))
                .GET().build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void unexpectedErrorAfterLogonAnswersJsonAndLogsOff() throws Exception {
        Map<String, ExtractionRestServer.Route> routes = new LinkedHashMap<>();
        routes.put("boom", new ExtractionRestServer.Route("throws after logging on", client -> {
            client.verify();
            throw new NullPointerException("simulated bug");
        }));
        start(vault(), routes);

        HttpResponse<String> response = get("boom");
        JsonNode body = MAPPER.readTree(response.body());

        assertEquals(502, response.statusCode());
        assertEquals("FAILED", body.get("status").asText());
        assertEquals("INTERNAL", body.get("error_kind").asText());
        assertTrue(body.get("error").asText().contains("NullPointerException"));
        assertEquals("ok", body.get("logoff").asText());
        assertEquals(0, mock.openPvwaSessions(), "session closed despite the error");

        // The busy flag was released: the next request runs instead of getting 409.
        assertEquals(502, get("boom").statusCode());
    }

    @Test
    void clientThatCannotBeCreatedStillGetsAJsonAnswer() throws Exception {
        Map<String, ExtractionRestServer.Route> routes = new LinkedHashMap<>();
        routes.put("any", new ExtractionRestServer.Route("never reached", client -> Map.of("status", "SUCCESS")));
        start(() -> {
            throw new IllegalStateException("cannot build client");
        }, routes);

        HttpResponse<String> response = get("any");
        JsonNode body = MAPPER.readTree(response.body());

        assertEquals(500, response.statusCode());
        assertEquals("FAILED", body.get("status").asText());
        assertEquals("INTERNAL", body.get("error_kind").asText());
    }

    @Test
    void secretsInACyberArkErrorBodyNeverReachTheResponseOrTheConsole() throws Exception {
        mock.fail(MockCyberArkServer.PVWA_ACCOUNTS, Fault.ERROR_WITH_SECRET);
        Map<String, ExtractionRestServer.Route> routes = new LinkedHashMap<>();
        routes.put("accounts-raw", new ExtractionRestServer.Route("one accounts page", client -> {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("status", "SUCCESS");
            result.put("data", client.get("/API/Accounts", Map.of()));
            return result;
        }));
        start(vault(), routes);

        HttpResponse<String> response = get("accounts-raw");

        assertEquals(502, response.statusCode());
        assertTrue(response.body().contains("MOCK500"), response.body());
        for (String secret : MockCyberArkServer.ERROR_BODY_SECRETS) {
            assertFalse(response.body().contains(secret), secret + " leaked to REST: " + response.body());
            assertFalse(console.toString(StandardCharsets.UTF_8).contains(secret), secret + " leaked to the console");
        }
        assertFalse(response.body().contains(MockCyberArkServer.MOCK_VAULT_PASSWORD));
    }

    @Test
    void accountRecordsReturnedByRestCarryNoSecretValues() throws Exception {
        Map<String, ExtractionRestServer.Route> routes = new LinkedHashMap<>();
        routes.put("accounts-raw", new ExtractionRestServer.Route("one accounts page", client -> {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("status", "SUCCESS");
            result.put("data", client.get("/API/Accounts", Map.of("limit", "1000")));
            return result;
        }));
        start(vault(), routes);

        HttpResponse<String> response = get("accounts-raw");

        assertEquals(200, response.statusCode());
        assertTrue(response.body().contains("\"secretType\""), "metadata kept");
        assertFalse(response.body().contains("MOCK-SECRET-VALUE"));
        assertFalse(response.body().contains("MOCK-NESTED-PASSWORD"));
        assertFalse(response.body().contains("\"secret\""));
        assertFalse(console.toString(StandardCharsets.UTF_8).contains("MOCK-SECRET-VALUE"));
    }
}
