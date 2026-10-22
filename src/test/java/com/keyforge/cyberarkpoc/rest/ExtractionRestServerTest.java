package com.keyforge.cyberarkpoc.rest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyforge.cyberarkpoc.client.PvwaClient;
import com.keyforge.cyberarkpoc.config.ConfigException;
import com.keyforge.cyberarkpoc.config.PvwaConfig;
import com.keyforge.cyberarkpoc.extract.ExtractionSettings;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer;
import com.keyforge.cyberarkpoc.store.DbConfig;
import com.keyforge.cyberarkpoc.mock.SampleData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The REST service end to end against the local mock (FABRICATED data). */
class ExtractionRestServerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private MockCyberArkServer mock;
    private ExtractionRestServer rest;

    @AfterEach
    void stop() {
        if (rest != null) {
            rest.stop();
        }
        if (mock != null) {
            mock.close();
        }
    }

    /** No database is configured in these tests: extraction routes must report that, not fail silently. */
    private static final Supplier<DbConfig> NO_DB = () -> {
        throw new ConfigException("Missing required database configuration: PG_HOST");
    };

    private void start(Supplier<PvwaClient> pvwa) throws Exception {
        rest = new ExtractionRestServer(new ExtractionRestServer.Settings("127.0.0.1", 0, "rest-user", "rest-pass"),
                pvwa, ExtractionRestServer.pvwaRoutes(NO_DB, ExtractionSettings.defaults()));
        rest.start();
    }

    private Supplier<PvwaClient> mockVault(String password) throws Exception {
        mock = MockCyberArkServer.start(SampleData.demo(), 0);
        PvwaConfig config = new PvwaConfig(URI.create(mock.rootUrl() + MockCyberArkServer.PVWA_APP), "CyberArk",
                MockCyberArkServer.MOCK_VAULT_USERNAME, password, Duration.ofSeconds(5), null);
        return () -> new PvwaClient(config);
    }

    private HttpResponse<String> get(String path, boolean withAuth) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + rest.port() + path)).GET();
        if (withAuth) {
            b.header("Authorization", "Basic " + Base64.getEncoder()
                    .encodeToString("rest-user:rest-pass".getBytes(StandardCharsets.UTF_8)));
        }
        return HttpClient.newHttpClient().send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void verifyRouteReturnsTheVaultDataAndLogsOff() throws Exception {
        start(mockVault(MockCyberArkServer.MOCK_VAULT_PASSWORD));

        HttpResponse<String> response = get("/cyberark-extract/pvwa/verify", true);
        JsonNode body = MAPPER.readTree(response.body());

        assertEquals(200, response.statusCode());
        assertEquals("SUCCESS", body.get("status").asText());
        assertEquals("MOCK Vault", body.get("data").get("ServerName").asText());
        assertEquals("ok", body.get("logoff").asText());
        assertEquals(1, body.get("logons").asInt());
        assertEquals(0, mock.openPvwaSessions());
    }

    @Test
    void requestsWithoutBasicAuthAreRejected() throws Exception {
        start(mockVault(MockCyberArkServer.MOCK_VAULT_PASSWORD));

        assertEquals(401, get("/cyberark-extract/pvwa/verify", false).statusCode());
        assertEquals(0, mock.requestCount(MockCyberArkServer.PVWA_LOGON), "nothing was called");
    }

    @Test
    void usageListsTheRoutesAndUnknownRoutesAre404() throws Exception {
        start(mockVault(MockCyberArkServer.MOCK_VAULT_PASSWORD));

        JsonNode usage = MAPPER.readTree(get("/cyberark-extract", true).body());
        assertTrue(usage.get("routes").has("pvwa/verify"));
        assertEquals(404, get("/cyberark-extract/pvwa/nothing", true).statusCode());
    }

    @Test
    void wrongVaultPasswordGivesAFailedRunWithTheReason() throws Exception {
        start(mockVault("wrong"));

        HttpResponse<String> response = get("/cyberark-extract/pvwa/verify", true);
        JsonNode body = MAPPER.readTree(response.body());

        assertEquals(502, response.statusCode());
        assertEquals("FAILED", body.get("status").asText());
        assertEquals("AUTHENTICATION", body.get("error_kind").asText());
        assertTrue(!response.body().contains("wrong"), "the vault password is never echoed");
    }

    @Test
    void safesRouteIsListedAndReportsMissingDatabaseSettings() throws Exception {
        start(mockVault(MockCyberArkServer.MOCK_VAULT_PASSWORD));

        JsonNode usage = MAPPER.readTree(get("/cyberark-extract", true).body());
        assertTrue(usage.get("routes").has("pvwa/safes"));

        HttpResponse<String> response = get("/cyberark-extract/pvwa/safes", true);
        JsonNode body = MAPPER.readTree(response.body());
        assertEquals(500, response.statusCode());
        assertEquals("CONFIG_ERROR", body.get("status").asText());
        assertTrue(body.get("error").asText().contains("PG_HOST"));
        assertEquals(0, mock.requestCount(MockCyberArkServer.PVWA_SAFES), "no CyberArk call without a database");
        assertEquals(0, mock.openPvwaSessions());
    }

    @Test
    void runStatusesMapToHttpLikePart2() {
        assertEquals(200, ExtractionRestServer.httpStatus("SUCCESS"));
        assertEquals(200, ExtractionRestServer.httpStatus("COMPLETED_WITH_FAILURES"));
        assertEquals(200, ExtractionRestServer.httpStatus("INCOMPLETE"));
        assertEquals(500, ExtractionRestServer.httpStatus("CONFIG_ERROR"));
        assertEquals(502, ExtractionRestServer.httpStatus("FAILED"));
    }

    @Test
    void missingVaultSettingsGiveAConfigError() throws Exception {
        start(() -> {
            throw new ConfigException(PvwaConfig.ENV_BASE_URL + " is required");
        });

        HttpResponse<String> response = get("/cyberark-extract/pvwa/verify", true);

        assertEquals(500, response.statusCode());
        assertEquals("CONFIG_ERROR", MAPPER.readTree(response.body()).get("status").asText());
    }
}
