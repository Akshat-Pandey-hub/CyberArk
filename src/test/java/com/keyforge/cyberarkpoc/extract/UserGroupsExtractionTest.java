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
 * User groups extraction: the official "Get groups" result served by a stub, and the local mock (FABRICATED data in
 * the documented shape) for paging, members, errors and redaction.
 */
class UserGroupsExtractionTest {

    private static final ExtractionSettings DEFAULT_PAGE = new ExtractionSettings(null, 0, 1000);
    private static final ExtractionSettings PAGE_OF_10 = new ExtractionSettings(10, 0, 1000);

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
        try (InputStream in = UserGroupsExtractionTest.class.getResourceAsStream("/official/" + name)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static FetchResult fetch(ExtractionSettings settings, PvwaClient c) {
        return PvwaExtraction.userGroups(settings).fetch().apply(c);
    }

    @Test
    void parsesTheOfficialResultWithEveryFieldMapped() throws Exception {
        stub = new StubHttpServer()
                .reply("/PasswordVault/API/auth/Cyberark/Logon/", 200, "\"stub-token\"")
                .reply("/PasswordVault/API/Auth/Logoff/", 200, "{}")
                .reply("/PasswordVault/API/UserGroups/", 200, fixture("pvwa-user-groups.official-derived.json"));

        FetchResult result = fetch(DEFAULT_PAGE, clientFor(stub.rootUrl(), "u", "p"));

        assertTrue(result.complete(), result.notes().toString());
        JsonNode g = result.records().get(0);
        assertEquals(0, g.get("id").asInt(), "id 0 is a valid id, not a missing one");
        assertEquals("Vault", g.get("groupType").asText());
        assertEquals(1, g.get("members").size());
    }

    @Test
    void sendsIncludeMembersAndPagesWithOffsetAndLimit() throws IOException {
        FetchResult result = fetch(PAGE_OF_10, mockClient(SampleData.demo()));

        assertTrue(result.complete(), result.notes().toString());
        assertEquals(30, result.records().size());
        assertEquals(30, result.reportedTotal());
        assertEquals(4, result.pages(), "30 groups in pages of 10; the third page is full, so one more (empty) page");
        assertEquals("includeMembers=true&offset=0&limit=10", mock.userGroupsQueries().get(0));
        assertEquals("includeMembers=true&offset=20&limit=10", mock.userGroupsQueries().get(2));
    }

    @Test
    void membersAndDirectoryFieldsArrive() throws IOException {
        FetchResult result = fetch(DEFAULT_PAGE, mockClient(SampleData.demo()));

        JsonNode admins = result.records().get(0);
        assertEquals("Administrator", admins.at("/members/0/username").asText());
        assertEquals(2, admins.at("/members/0/id").asInt());
        assertFalse(admins.has("dn"), "dn exists only for Directory groups");
        JsonNode directory = result.records().get(2);
        assertEquals("Directory", directory.get("groupType").asText());
        assertEquals("mock.example.test", directory.get("directory").asText());
        assertTrue(directory.get("dn").asText().startsWith("CN=MOCK LDAP Readers,"));
        assertEquals(0, result.records().get(3).get("members").size(), "an empty group keeps an empty list");
    }

    @Test
    void aCountThatDiffersFromTheGroupsReceivedMarksTheResultIncomplete() throws IOException {
        PvwaClient c = mockClient(SampleData.demo());
        mock.fail(MockCyberArkServer.PVWA_USER_GROUPS, Fault.WRONG_COUNT);

        FetchResult result = fetch(DEFAULT_PAGE, c);

        assertFalse(result.complete());
        assertTrue(result.notes().toString().contains("reported count 31 but 30"), result.notes().toString());
    }

    @Test
    void aServerIgnoringOffsetIsDetected() throws IOException {
        PvwaClient c = mockClient(SampleData.demo());
        mock.fail(MockCyberArkServer.PVWA_USER_GROUPS, Fault.IGNORE_OFFSET);

        FetchResult result = fetch(PAGE_OF_10, c);

        assertFalse(result.complete());
        assertEquals(10, result.records().size());
    }

    @Test
    void withoutAuditUsersTheRunFails() throws IOException {
        PvwaClient c = mockClient(SampleData.demo());
        mock.fail(MockCyberArkServer.PVWA_USER_GROUPS, Fault.HTTP_403);

        CyberArkApiException e = assertThrows(CyberArkApiException.class, () -> fetch(DEFAULT_PAGE, c));
        assertEquals(CyberArkApiException.Kind.AUTHENTICATION, e.kind());
    }

    @Test
    void secretsAreRemovedAndUnexpectedFieldsAreReported() throws IOException {
        MockDataset data = new MockDataset().userGroup(7, "G7", "Vault", "u:9")
                .withUserGroupField("Secret", "MOCK-GROUP-SECRET")
                .withUserGroupField("mockExtraField", "x");
        PvwaExtraction groups = PvwaExtraction.userGroups(DEFAULT_PAGE);

        FetchResult result = groups.fetch().apply(mockClient(data));

        assertFalse(result.records().toString().contains("MOCK-GROUP-SECRET"));
        assertTrue(result.records().get(0).has("mockExtraField"), "an unexpected field is kept, not dropped");
    }
}
