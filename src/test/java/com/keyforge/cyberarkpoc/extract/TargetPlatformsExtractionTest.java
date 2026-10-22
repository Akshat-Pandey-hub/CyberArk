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
 * Target platforms extraction: the official "Get target platforms" example served verbatim by a stub, and the local
 * mock (FABRICATED data in the documented example shape).
 */
class TargetPlatformsExtractionTest {

    private static final String PATH = "/PasswordVault/API/platforms/targets/";

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

    private PvwaClient stubClient(String targetsBody) {
        stub = new StubHttpServer()
                .reply("/PasswordVault/API/auth/Cyberark/Logon/", 200, "\"stub-token\"")
                .reply("/PasswordVault/API/Auth/Logoff/", 200, "{}")
                .reply(PATH, 200, targetsBody);
        return clientFor(stub.rootUrl(), "u", "p");
    }

    private static String fixture(String name) throws IOException {
        try (InputStream in = TargetPlatformsExtractionTest.class.getResourceAsStream("/official/" + name)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static FetchResult fetch(PvwaClient c) {
        return PvwaExtraction.targetPlatforms().fetch().apply(c);
    }

    @Test
    void parsesTheOfficialExampleVerbatimWithEveryFieldMapped() throws Exception {
        FetchResult result = fetch(stubClient(fixture("pvwa-target-platforms.official-example.json")));

        assertTrue(result.complete(), result.notes().toString());
        assertEquals(1, result.reportedTotal());
        assertEquals(1, result.pages(), "one request, no paging");
        JsonNode p = result.records().get(0);
        assertEquals(10, p.get("ID").asInt());
        assertEquals("WinDesktopLocal", p.get("PlatformID").asText());
        assertEquals(".*", p.get("AllowedSafes").asText());
        assertEquals(90, p.at("/CredentialsManagementPolicy/Change/RequirePasswordEveryXDays").asInt());
        assertTrue(p.at("/PrivilegedAccessWorkflows/RequireUsersToSpecifyReasonForAccess/IsActive").asBoolean());
        List<String> columns = PvwaExtraction.TARGET_PLATFORM_COLUMNS.stream().map(Column::name).toList();
        p.fieldNames().forEachRemaining(f -> assertTrue(columns.contains(f), f + " has no column"));
        assertEquals(columns.size(), p.size(), "every column is present in the example");
    }

    @Test
    void readsEveryPlatformFromTheMockIncludingInactiveOnes() throws IOException {
        FetchResult result = fetch(mockClient(SampleData.demo()));

        assertTrue(result.complete(), result.notes().toString());
        assertEquals(List.of("WinDesktopLocal", "WinServerLocal", "UnixSSH"),
                result.records().stream().map(r -> r.get("PlatformID").asText()).toList());
        assertFalse(result.records().get(2).get("Active").asBoolean());
    }

    @Test
    void aTotalThatDiffersFromTheRecordsMarksTheResultIncomplete() throws IOException {
        PvwaClient c = mockClient(SampleData.demo());
        mock.fail(MockCyberArkServer.PVWA_TARGET_PLATFORMS, Fault.WRONG_COUNT);

        FetchResult result = fetch(c);

        assertFalse(result.complete());
        assertTrue(result.notes().toString().contains("Total 4 but 3"), result.notes().toString());
    }

    @Test
    void aResponseWithoutThePlatformsArrayIsInvalid() {
        CyberArkApiException e = assertThrows(CyberArkApiException.class,
                () -> fetch(stubClient("{\"value\": [], \"count\": 0}")));
        assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE, e.kind());
    }

    @Test
    void fieldTableCasingIsReportedInsteadOfBeingStoredEmpty() {
        // The field table's camelCase, grouped shape: no PlatformID, so nothing can be keyed or stored.
        PvwaClient c = stubClient("{\"Platforms\": [{\"general\": {\"id\": 10, \"platformID\": \"WinDesktopLocal\"}, "
                + "\"credentialsManagement\": {}}], \"Total\": 1}");
        PvwaExtraction targets = PvwaExtraction.targetPlatforms();

        FetchResult result = targets.fetch().apply(c);

        assertEquals(0, result.records().size());
        assertEquals(1, result.missingId());
        assertTrue(result.notes().toString().contains("had no 'PlatformID'"), result.notes().toString());
    }

    @Test
    void duplicatePlatformsAreDroppedAndTheMismatchIsNoted() {
        PvwaClient c = stubClient("{\"Platforms\": [{\"PlatformID\": \"A\", \"ID\": 1}, {\"PlatformID\": \"A\", \"ID\": 1}], "
                + "\"Total\": 2}");

        FetchResult result = fetch(c);

        assertEquals(1, result.records().size());
        assertFalse(result.complete(), "Total 2 but only 1 distinct platform");
        assertTrue(result.notes().toString().contains("duplicate"), result.notes().toString());
    }

    @Test
    void secretsAreRemovedAndUnexpectedFieldsAreReported() throws IOException {
        MockDataset data = new MockDataset()
                .targetPlatform(1, "P1", "P one", "Windows", true, 30)
                .withTargetPlatformField("Password", "MOCK-PLATFORM-PASSWORD")
                .withTargetPlatformField("mockExtraField", "x");
        PvwaExtraction targets = PvwaExtraction.targetPlatforms();

        FetchResult result = targets.fetch().apply(mockClient(data));

        assertFalse(result.records().toString().contains("MOCK-PLATFORM-PASSWORD"));
        assertEquals(List.of("mockExtraField"), ExtractionRunner.fieldsWithoutColumn(result, targets));
    }

    @Test
    void aPermissionErrorFailsTheRun() throws IOException {
        PvwaClient c = mockClient(SampleData.demo());
        mock.fail(MockCyberArkServer.PVWA_TARGET_PLATFORMS, Fault.HTTP_403);

        CyberArkApiException e = assertThrows(CyberArkApiException.class, () -> fetch(c));
        assertEquals(CyberArkApiException.Kind.AUTHENTICATION, e.kind());
    }
}
