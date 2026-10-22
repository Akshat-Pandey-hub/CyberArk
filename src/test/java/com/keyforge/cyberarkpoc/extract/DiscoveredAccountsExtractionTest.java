package com.keyforge.cyberarkpoc.extract;

import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.StubHttpServer;
import com.keyforge.cyberarkpoc.client.CyberArkApiException;
import com.keyforge.cyberarkpoc.client.PvwaClient;
import com.keyforge.cyberarkpoc.config.PvwaConfig;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer.Fault;
import com.keyforge.cyberarkpoc.mock.MockDataset;
import com.keyforge.cyberarkpoc.mock.SampleData;
import com.keyforge.cyberarkpoc.store.Column;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Discovered accounts extraction: the official "Get discovered accounts" example records served by a stub, and the
 * local mock (FABRICATED data in the documented shape) for paging, errors, scope reporting and redaction.
 */
class DiscoveredAccountsExtractionTest {

    private static final ExtractionSettings DEFAULT_PAGE = new ExtractionSettings(null, 0, 1000);

    private MockCyberArkServer mock;
    private StubHttpServer stub;
    private PvwaClient client;

    @AfterEach
    void stop() {
        if (client != null) {
            client.close();
        }
        if (mock != null) {
            mock.close();
        }
        if (stub != null) {
            stub.close();
        }
    }

    private PvwaClient clientFor(String root, String user, String password) {
        client = new PvwaClient(new PvwaConfig(URI.create(root + MockCyberArkServer.PVWA_APP), "CyberArk", user,
                password, Duration.ofSeconds(5), null));
        return client;
    }

    private PvwaClient mockClient(MockDataset data) throws IOException {
        mock = MockCyberArkServer.start(data, 0);
        return clientFor(mock.rootUrl(), MockCyberArkServer.MOCK_VAULT_USERNAME, MockCyberArkServer.MOCK_VAULT_PASSWORD);
    }

    private static String fixture(String name) throws IOException {
        try (InputStream in = DiscoveredAccountsExtractionTest.class.getResourceAsStream("/official/" + name)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static FetchResult fetch(PvwaClient c) {
        return PvwaExtraction.discoveredAccounts(DEFAULT_PAGE).fetch().apply(c);
    }

    @Test
    void parsesTheOfficialExampleRecordsWithEveryFieldMapped() throws Exception {
        stub = new StubHttpServer()
                .reply("/PasswordVault/API/auth/Cyberark/Logon/", 200, "\"stub-token\"")
                .reply("/PasswordVault/API/Auth/Logoff/", 200, "{}")
                .reply("/PasswordVault/API/DiscoveredAccounts/", 200,
                        fixture("pvwa-discovered-accounts.official-derived.json"));

        FetchResult result = fetch(clientFor(stub.rootUrl(), "u", "p"));

        assertTrue(result.complete(), result.notes().toString());
        assertEquals(3, result.records().size());
        JsonNode windows = result.records().get(0);
        assertEquals("18_5", windows.get("id").asText());
        assertEquals(1530635786L, windows.get("lastPasswordSetDateTime").asLong());
        assertEquals("S-1-5-21-304654729-3147011263-1431158397-3154",
                windows.at("/platformTypeAccountProperties/SID").asText());
        assertEquals(445, windows.at("/additionalProperties/Port").asInt());
        JsonNode aws = result.records().get(1);
        assertEquals(1530635688L, aws.get("discoveryDate").asLong(), "the example's discoveryDate is kept as sent");
        assertFalse(aws.has("osVersion"), "only populated properties are returned");
        List<String> columns = PvwaExtraction.DISCOVERED_ACCOUNT_COLUMNS.stream().map(Column::name).toList();
        for (JsonNode r : result.records()) {
            r.fieldNames().forEachRemaining(f -> assertTrue(columns.contains(f), f + " has no column"));
        }
    }

    @Test
    void readsEveryPageWithTheDocumentedDefaultLimit() throws IOException {
        FetchResult result = fetch(mockClient(SampleData.demo()));

        assertTrue(result.complete(), result.notes().toString());
        assertEquals(130, result.records().size());
        assertEquals(130, result.reportedTotal());
        assertEquals(2, result.pages(), "130 accounts with the documented default limit 100");
        assertEquals("18_902", result.records().get(129).get("id").asText());
    }

    @Test
    void theScopeNoteIsAlwaysReportedEvenWhenNothingIsPending() throws IOException {
        FetchResult result = fetch(mockClient(new MockDataset()));

        assertTrue(result.complete());
        assertEquals(0, result.records().size());
        assertTrue(result.notes().contains(PvwaExtraction.DISCOVERY_SCOPE_NOTE),
                "an empty list must never read as 'no accounts exist'");
    }

    @Test
    void aCountThatDiffersFromTheAccountsReceivedMarksTheResultIncomplete() throws IOException {
        PvwaClient c = mockClient(SampleData.demo());
        mock.fail(MockCyberArkServer.PVWA_DISCOVERED_ACCOUNTS, Fault.WRONG_COUNT);

        FetchResult result = fetch(c);

        assertFalse(result.complete());
        assertTrue(result.notes().toString().contains("reported count 131 but 130"), result.notes().toString());
        assertTrue(result.notes().contains(PvwaExtraction.DISCOVERY_SCOPE_NOTE));
    }

    @Test
    void withoutVaultAdminsOrFeedAdminsTheRunFails() throws IOException {
        PvwaClient c = mockClient(SampleData.demo());
        mock.fail(MockCyberArkServer.PVWA_DISCOVERED_ACCOUNTS, Fault.HTTP_403);

        CyberArkApiException e = assertThrows(CyberArkApiException.class, () -> fetch(c));
        assertEquals(CyberArkApiException.Kind.AUTHENTICATION, e.kind());
        assertEquals(403, e.httpStatus());
    }

    @Test
    void secretsAreRemovedAndUnexpectedFieldsAreReported() throws IOException {
        MockDataset data = new MockDataset().discoveredAccountBody("{\"id\": \"1_1\", \"userName\": \"u\", "
                + "\"platformTypeAccountProperties\": {\"awsAccountID\": \"1\", \"secret\": \"MOCK-DISCOVERED-SECRET\"}, "
                + "\"mockExtraField\": 1}");
        PvwaExtraction discovered = PvwaExtraction.discoveredAccounts(DEFAULT_PAGE);

        FetchResult result = discovered.fetch().apply(mockClient(data));

        assertFalse(result.records().toString().contains("MOCK-DISCOVERED-SECRET"));
        assertEquals("1", result.records().get(0).at("/platformTypeAccountProperties/awsAccountID").asText());
        assertEquals(List.of("mockExtraField"), ExtractionRunner.fieldsWithoutColumn(result, discovered));
    }
}
