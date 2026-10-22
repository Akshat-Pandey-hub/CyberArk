package com.keyforge.cyberarkpoc.extract;

import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.client.CyberArkApiException;
import com.keyforge.cyberarkpoc.client.PvwaClient;
import com.keyforge.cyberarkpoc.config.PvwaConfig;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer.Fault;
import com.keyforge.cyberarkpoc.mock.SampleData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Accounts extraction against the local mock (FABRICATED data in the documented "Get accounts" shape). */
class AccountsExtractionTest {

    private static final ExtractionSettings FAST = new ExtractionSettings(null, 0, 1000);

    private MockCyberArkServer mock;
    private PvwaClient client;

    @BeforeEach
    void start() throws IOException {
        mock = MockCyberArkServer.start(SampleData.demo(), 0);
        client = new PvwaClient(new PvwaConfig(URI.create(mock.rootUrl() + MockCyberArkServer.PVWA_APP), "CyberArk",
                MockCyberArkServer.MOCK_VAULT_USERNAME, MockCyberArkServer.MOCK_VAULT_PASSWORD,
                Duration.ofSeconds(5), null));
    }

    @AfterEach
    void stop() {
        client.close();
        mock.close();
    }

    @Test
    void readsAllPagesWithTheDocumentedDefaultPageSize() {
        FetchResult result = PvwaExtraction.accounts(FAST).fetch().apply(client);

        assertEquals(120, result.records().size());
        assertEquals(3, result.pages(), "120 accounts with the documented default limit 50");
        assertTrue(result.complete(), result.notes().toString());
        assertEquals("12_120", result.records().get(119).get("id").asText());
    }

    @Test
    void secretValuesAreRemovedAtEveryDepthAndMetadataIsKept() {
        FetchResult result = PvwaExtraction.accounts(FAST).fetch().apply(client);

        String all = result.records().toString();
        assertFalse(all.contains("MOCK-SECRET-VALUE"), "no secret value in any record");
        assertFalse(all.contains("MOCK-NESTED-PASSWORD"), "nested password removed too");
        JsonNode first = result.records().get(0);
        assertFalse(first.has("secret"));
        assertFalse(first.get("platformAccountProperties").has("Password"));
        assertEquals("password", first.get("secretType").asText());
        assertEquals("success", first.get("secretManagement").get("status").asText());
        assertEquals("IT", first.get("platformAccountProperties").get("Location").asText());
    }

    @Test
    void permissionErrorIsReported() {
        mock.fail(MockCyberArkServer.PVWA_ACCOUNTS, Fault.HTTP_403);
        CyberArkApiException e = assertThrows(CyberArkApiException.class,
                () -> PvwaExtraction.accounts(FAST).fetch().apply(client));

        assertEquals(CyberArkApiException.Kind.AUTHENTICATION, e.kind());
        assertEquals(403, e.httpStatus());
    }

    @Test
    void reportedCountMismatchIsIncomplete() {
        mock.fail(MockCyberArkServer.PVWA_ACCOUNTS, Fault.WRONG_COUNT);
        FetchResult result = PvwaExtraction.accounts(FAST).fetch().apply(client);

        assertFalse(result.complete());
    }

    @Test
    void secretsInAnErrorBodyNeverReachTheExceptionMessage() {
        mock.fail(MockCyberArkServer.PVWA_ACCOUNTS, Fault.ERROR_WITH_SECRET);
        CyberArkApiException e = assertThrows(CyberArkApiException.class,
                () -> PvwaExtraction.accounts(FAST).fetch().apply(client));

        assertEquals(500, e.httpStatus());
        assertTrue(e.getMessage().contains("MOCK500"), "the error code is still useful: " + e.getMessage());
        for (String secret : MockCyberArkServer.ERROR_BODY_SECRETS) {
            assertFalse(e.getMessage().contains(secret), secret + " leaked: " + e.getMessage());
        }
    }

    @Test
    void sanitizeMasksTheVaultPasswordAndSessionTokens() {
        client.verify(); // logs on, so a session token exists
        String text = client.sanitize("pw " + MockCyberArkServer.MOCK_VAULT_PASSWORD + " token mock-pvwa-session-");

        assertFalse(text.contains(MockCyberArkServer.MOCK_VAULT_PASSWORD));
    }
}
