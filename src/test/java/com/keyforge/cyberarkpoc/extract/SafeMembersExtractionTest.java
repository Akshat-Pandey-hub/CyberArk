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
 * Safe members extraction: the official "Get all Safe members" example served verbatim by a stub, and the local mock
 * (FABRICATED data in the documented shape) for paging, per-Safe failures and redaction.
 */
class SafeMembersExtractionTest {

    private static final ExtractionSettings FAST = new ExtractionSettings(null, 0, 1000);

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
        try (InputStream in = SafeMembersExtractionTest.class.getResourceAsStream("/official/" + name)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test
    void parsesTheOfficialExampleWithEveryDocumentedField() throws Exception {
        stub = new StubHttpServer()
                .reply("/PasswordVault/API/auth/Cyberark/Logon/", 200, "\"stub-token\"")
                .reply("/PasswordVault/API/Auth/Logoff/", 200, "{}")
                .reply("/PasswordVault/API/Safes/", 200,
                        "{\"value\": [{\"safeUrlId\": \"BZ_I_87\", \"safeName\": \"BZ_I_87\"}], \"count\": 1}")
                .reply("/PasswordVault/API/Safes/BZ_I_87/Members/", 200,
                        fixture("pvwa-safe-members.official-derived.json"));

        FetchResult result = PvwaExtraction.safeMembers(FAST).fetch().apply(clientFor(stub.rootUrl(), "u", "p"));

        assertTrue(result.complete(), result.notes().toString());
        assertEquals(1, result.records().size());
        JsonNode m = result.records().get(0);
        assertEquals("BZ_I_87", m.get("safeUrlId").asText());
        assertEquals(37, m.get("safeNumber").asInt());
        assertEquals(0, m.get("memberId").asInt(), "memberId 0 is a valid id, not a missing one");
        assertEquals("Master", m.get("memberName").asText());
        assertEquals("User", m.get("memberType").asText());
        assertTrue(m.get("membershipExpirationDate").isNull());
        assertTrue(m.get("isPredefinedUser").asBoolean());
        assertEquals(22, m.get("permissions").size(), "all 22 documented permission flags");
        assertFalse(m.has("isReadOnly"), "in the field table but not in the example; stored as NULL");
    }

    @Test
    void readsEverySafeAndPagesAMemberListLongerThanTheDefaultLimit() throws IOException {
        FetchResult result = PvwaExtraction.safeMembers(FAST).fetch().apply(mockClient(SampleData.demo()));

        assertTrue(result.complete(), result.notes().toString());
        assertEquals(88, result.records().size(), "30 Safes x 2 members + 28 more in MOCK-Safe-01");
        assertEquals(30, result.records().stream().filter(r -> r.get("memberId").asLong() == 1).count(),
                "the same group (memberId 1) is kept once per Safe, not deduplicated across Safes");
        assertEquals(2 + 30 + 1, result.pages(), "2 Safe pages + 1 page per Safe + 1 extra page for MOCK-Safe-01");
    }

    @Test
    void aSafeWithoutViewSafeMembersMakesTheRunIncompleteButKeepsTheOthers() throws IOException {
        PvwaClient c = mockClient(SampleData.demo());
        mock.forbidSafeMembers("MOCK-Safe-05");

        FetchResult result = PvwaExtraction.safeMembers(FAST).fetch().apply(c);

        assertFalse(result.complete());
        assertEquals(86, result.records().size());
        assertTrue(result.notes().toString().contains("MOCK-Safe-05") && result.notes().toString().contains("403"),
                result.notes().toString());
        assertEquals(1, mock.openPvwaSessions(), "one session for the whole run (logged off when the client closes)");
    }

    @Test
    void whenNoSafeCanBeReadTheRunFails() throws IOException {
        MockDataset data = new MockDataset().safe("S1", "S1", 1).safe("S2", "S2", 2);
        PvwaClient c = mockClient(data);
        mock.forbidSafeMembers("S1");
        mock.forbidSafeMembers("S2");

        CyberArkApiException e = assertThrows(CyberArkApiException.class,
                () -> PvwaExtraction.safeMembers(FAST).fetch().apply(c));
        assertEquals(CyberArkApiException.Kind.AUTHENTICATION, e.kind());
        assertEquals(403, e.httpStatus());
    }

    @Test
    void aSafeIdThatCannotBeUsedInAUrlIsReportedNotCalled() throws IOException {
        MockDataset data = new MockDataset().safe("Bad Safe", "Bad Safe", 1).safe("Good", "Good", 2)
                .safeMember("Good", "Good", 2, 7, "u7", "User");

        FetchResult result = PvwaExtraction.safeMembers(FAST).fetch().apply(mockClient(data));

        assertFalse(result.complete());
        assertEquals(1, result.records().size());
        assertTrue(result.notes().toString().contains("Bad Safe"), result.notes().toString());
    }

    @Test
    void wrongReportedCountForOneSafeMarksTheRunIncomplete() throws IOException {
        PvwaClient c = mockClient(SampleData.demo());
        mock.fail(MockCyberArkServer.PVWA_SAFE_MEMBERS, Fault.WRONG_COUNT);

        FetchResult result = PvwaExtraction.safeMembers(FAST).fetch().apply(c);

        assertFalse(result.complete());
        assertTrue(result.notes().toString().contains("reported count"), result.notes().toString());
    }

    @Test
    void secretsAreRemovedAndUnexpectedFieldsAreReported() throws IOException {
        MockDataset data = new MockDataset().safe("S1", "S1", 1)
                .safeMember("S1", "S1", 1, 5, "u5", "User")
                .withSafeMemberField("S1", "password", "MOCK-MEMBER-PASSWORD")
                .withSafeMemberField("S1", "mockExtraField", "x");
        PvwaExtraction members = PvwaExtraction.safeMembers(FAST);

        FetchResult result = members.fetch().apply(mockClient(data));

        assertFalse(result.records().toString().contains("MOCK-MEMBER-PASSWORD"));
        assertTrue(result.records().get(0).has("mockExtraField"), "an unexpected field is kept, not dropped");
    }
}
