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
 * Platform details extraction: a body built from the official "Get platform details" template (served by a stub,
 * after the official target-platforms example), and the local mock (FABRICATED data) for several platforms, errors and
 * redaction.
 */
class PlatformDetailsExtractionTest {

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

    private PvwaClient stubClient(String detailsBody) throws IOException {
        stub = new StubHttpServer()
                .reply("/PasswordVault/API/auth/Cyberark/Logon/", 200, "\"stub-token\"")
                .reply("/PasswordVault/API/Auth/Logoff/", 200, "{}")
                .reply("/PasswordVault/API/platforms/targets/", 200, fixture("pvwa-target-platforms.official-example.json"))
                .reply("/PasswordVault/API/Platforms/WinDesktopLocal/", 200, detailsBody);
        return clientFor(stub.rootUrl(), "u", "p");
    }

    private static String fixture(String name) throws IOException {
        try (InputStream in = PlatformDetailsExtractionTest.class.getResourceAsStream("/official/" + name)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static FetchResult fetch(PvwaClient c) {
        return PvwaExtraction.platformDetails().fetch().apply(c);
    }

    @Test
    void readsTheDetailsOfTheListedPlatformWithEveryDocumentedField() throws Exception {
        FetchResult result = fetch(stubClient(fixture("pvwa-platform-details.official-template-derived.json")));

        assertTrue(result.complete(), result.notes().toString());
        assertEquals(2, result.pages(), "the target list, then one call for its one platform");
        JsonNode d = result.records().get(0);
        assertEquals("WinDesktopLocal", d.get("PlatformID").asText());
        assertTrue(d.get("Active").asBoolean());
        assertEquals("Windows Desktop Local Accounts", d.at("/Properties/PolicyName").asText());
    }

    @Test
    void propertiesAsAKeyValueArrayAreKeptUnchanged() throws Exception {
        String body = "{\"PlatformID\": \"WinDesktopLocal\", \"Properties\": [{\"Key\": \"PolicyID\", "
                + "\"Value\": \"WinDesktopLocal\"}], \"Active\": true}";

        FetchResult result = fetch(stubClient(body));

        JsonNode properties = result.records().get(0).get("Properties");
        assertTrue(properties.isArray(), "the undocumented shape is not converted");
        assertEquals("PolicyID", properties.get(0).get("Key").asText());
    }

    @Test
    void readsOneDetailsCallPerPlatform() throws IOException {
        FetchResult result = fetch(mockClient(SampleData.demo()));

        assertTrue(result.complete(), result.notes().toString());
        assertEquals(List.of("WinDesktopLocal", "WinServerLocal", "UnixSSH"),
                result.records().stream().map(r -> r.get("PlatformID").asText()).toList());
        assertEquals(4, result.pages(), "1 list call + 3 details calls");
        assertEquals("30", result.records().get(1).at("/Properties/RequirePasswordChangeEveryXDays").asText());
        assertFalse(result.records().get(2).get("Active").asBoolean());
    }

    @Test
    void aPlatformThatCannotBeReadMakesTheRunIncompleteButKeepsTheOthers() throws IOException {
        PvwaClient c = mockClient(SampleData.demo());
        mock.forbidPlatformDetails("WinServerLocal");

        FetchResult result = fetch(c);

        assertFalse(result.complete());
        assertEquals(2, result.records().size());
        String notes = result.notes().toString();
        assertTrue(notes.contains("Platform WinServerLocal") && notes.contains("403"), notes);
    }

    @Test
    void whenNoPlatformCanBeReadTheRunFails() throws IOException {
        PvwaClient c = mockClient(SampleData.demo());
        mock.fail(MockCyberArkServer.PVWA_PLATFORM_DETAILS, Fault.HTTP_500);

        CyberArkApiException e = assertThrows(CyberArkApiException.class, () -> fetch(c));
        assertEquals(500, e.httpStatus());
    }

    @Test
    void detailsWithoutPlatformIdAreCountedNotStored() throws IOException {
        MockDataset data = new MockDataset().targetPlatform(1, "P1", "P one", "Windows", true, 30)
                .platformDetailsBody("P1", "{\"Properties\": {}, \"Active\": true}");

        FetchResult result = fetch(mockClient(data));

        assertEquals(0, result.records().size());
        assertEquals(1, result.missingId());
        assertTrue(result.notes().toString().contains("had no 'PlatformID'"), result.notes().toString());
    }

    @Test
    void aPlatformIdThatCannotBeUsedInAUrlIsReportedNotCalled() throws IOException {
        MockDataset data = new MockDataset().targetPlatform(1, "Bad Platform", "Bad", "Windows", true, 30)
                .targetPlatform(2, "Good", "Good", "Windows", true, 30);

        FetchResult result = fetch(mockClient(data));

        assertFalse(result.complete());
        assertEquals(1, result.records().size());
        assertTrue(result.notes().toString().contains("Bad Platform"), result.notes().toString());
    }

    @Test
    void secretsInsidePropertiesAreRemovedAndUnexpectedFieldsAreReported() throws IOException {
        MockDataset data = new MockDataset().targetPlatform(1, "P1", "P one", "Windows", true, 30)
                .platformDetailsBody("P1", "{\"PlatformID\": \"P1\", \"Properties\": {\"PolicyID\": \"P1\", "
                        + "\"Password\": \"MOCK-PLATFORM-PASSWORD\"}, \"Active\": true, \"mockExtraField\": 1}");
        PvwaExtraction details = PvwaExtraction.platformDetails();

        FetchResult result = details.fetch().apply(mockClient(data));

        assertFalse(result.records().toString().contains("MOCK-PLATFORM-PASSWORD"));
        assertEquals("P1", result.records().get(0).at("/Properties/PolicyID").asText());
        assertTrue(result.records().get(0).has("mockExtraField"), "an unexpected field is kept, not dropped");
    }
}
