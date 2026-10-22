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
 * Users extraction: the official "Get users" example served verbatim by a stub, and the local mock (FABRICATED data
 * in the documented shape) for paging, extended details, errors and redaction.
 */
class UsersExtractionTest {

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
        try (InputStream in = UsersExtractionTest.class.getResourceAsStream("/official/" + name)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test
    void parsesTheOfficialExampleVerbatimWithEveryFieldMapped() throws Exception {
        stub = new StubHttpServer()
                .reply("/PasswordVault/API/auth/Cyberark/Logon/", 200, "\"stub-token\"")
                .reply("/PasswordVault/API/Auth/Logoff/", 200, "{}")
                .reply("/PasswordVault/API/Users/", 200, fixture("pvwa-users.official-example.json"));

        FetchResult result = PvwaExtraction.users(DEFAULT_PAGE).fetch().apply(clientFor(stub.rootUrl(), "u", "p"));

        assertTrue(result.complete(), result.notes().toString());
        assertEquals(1, result.reportedTotal());
        JsonNode u = result.records().get(0);
        assertEquals(2, u.get("id").asInt());
        assertEquals("Administrator", u.get("username").asText());
        assertEquals(3, u.get("groupsMembership").size());
        assertEquals(16, u.get("groupsMembership").get(0).get("groupID").asInt(), "nested names kept as published");
        assertEquals(10, u.get("vaultAuthorization").size());
        assertEquals("\\", u.get("location").asText());
        assertEquals("Grey", u.at("/personalDetails/lastName").asText());
        List<String> columns = PvwaExtraction.USER_COLUMNS.stream().map(Column::name).toList();
        u.fieldNames().forEachRemaining(f -> assertTrue(columns.contains(f), f + " has no column"));
    }

    @Test
    void sendsExtendedDetailsAndTheDocumentedPagingParameters() throws IOException {
        FetchResult result = PvwaExtraction.users(PAGE_OF_10).fetch().apply(mockClient(SampleData.demo()));

        assertTrue(result.complete(), result.notes().toString());
        assertEquals(30, result.records().size());
        assertEquals(30, result.reportedTotal());
        assertEquals(4, result.pages(), "30 users in pages of 10; the third page is full, so one more (empty) page");
        assertEquals(List.of("ExtendedDetails=true&pageOffset=0&pageSize=10",
                "ExtendedDetails=true&pageOffset=10&pageSize=10", "ExtendedDetails=true&pageOffset=20&pageSize=10",
                "ExtendedDetails=true&pageOffset=30&pageSize=10"), mock.usersQueries().subList(0, 4));
    }

    @Test
    void extendedDetailsFieldsArrive() throws IOException {
        FetchResult result = PvwaExtraction.users(DEFAULT_PAGE).fetch().apply(mockClient(SampleData.demo()));

        JsonNode ldap = result.records().get(1);
        assertEquals("CN=mock.ldap.user,OU=Mock,DC=example,DC=test", ldap.get("userDN").asText());
        assertEquals("MOCK Org", ldap.at("/personalDetails/organization").asText());
        JsonNode suspended = result.records().get(2);
        assertTrue(suspended.get("suspended").asBoolean());
        assertFalse(result.records().get(3).get("enabled").asBoolean());
        assertFalse(result.records().get(0).has("userDN"), "only LDAP users have a userDN");
        assertEquals(1, result.pages(), "30 users fit in one page of the default 1000");
    }

    @Test
    void aTotalThatDiffersFromTheUsersReceivedMarksTheResultIncomplete() throws IOException {
        PvwaClient c = mockClient(SampleData.demo());
        mock.fail(MockCyberArkServer.PVWA_USERS, Fault.WRONG_COUNT);

        FetchResult result = PvwaExtraction.users(DEFAULT_PAGE).fetch().apply(c);

        assertFalse(result.complete());
        assertTrue(result.notes().toString().contains("reported Total 31 but 30"), result.notes().toString());
    }

    @Test
    void aServerIgnoringPageOffsetIsDetectedInsteadOfDuplicatingUsers() throws IOException {
        PvwaClient c = mockClient(SampleData.demo());
        mock.fail(MockCyberArkServer.PVWA_USERS, Fault.IGNORE_OFFSET);

        FetchResult result = PvwaExtraction.users(PAGE_OF_10).fetch().apply(c);

        assertFalse(result.complete());
        assertEquals(10, result.records().size(), "the repeated first page is not stored twice");
        assertTrue(result.notes().toString().contains("no progress"), result.notes().toString());
    }

    @Test
    void withoutAuditUsersTheRunFails() throws IOException {
        PvwaClient c = mockClient(SampleData.demo());
        mock.fail(MockCyberArkServer.PVWA_USERS, Fault.HTTP_403);

        CyberArkApiException e = assertThrows(CyberArkApiException.class,
                () -> PvwaExtraction.users(DEFAULT_PAGE).fetch().apply(c));
        assertEquals(CyberArkApiException.Kind.AUTHENTICATION, e.kind());
        assertEquals(403, e.httpStatus());
    }

    @Test
    void aResponseWithoutTheUsersArrayIsInvalid() {
        stub = new StubHttpServer()
                .reply("/PasswordVault/API/auth/Cyberark/Logon/", 200, "\"stub-token\"")
                .reply("/PasswordVault/API/Auth/Logoff/", 200, "{}")
                .reply("/PasswordVault/API/Users/", 200, "{\"value\": [], \"count\": 0}");
        PvwaClient c = clientFor(stub.rootUrl(), "u", "p");

        CyberArkApiException e = assertThrows(CyberArkApiException.class,
                () -> PvwaExtraction.users(DEFAULT_PAGE).fetch().apply(c));
        assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE, e.kind());
    }

    @Test
    void secretsAreRemovedAndUnexpectedFieldsAreReported() throws IOException {
        MockDataset data = new MockDataset().vaultUser(9, "u9", "CyberArk", "EPVUser", true, false)
                .withVaultUserField("password", "MOCK-USER-PASSWORD")
                .withVaultUserField("mockExtraField", "x");
        PvwaExtraction users = PvwaExtraction.users(DEFAULT_PAGE);

        FetchResult result = users.fetch().apply(mockClient(data));

        assertFalse(result.records().toString().contains("MOCK-USER-PASSWORD"));
        assertEquals(List.of("mockExtraField"), ExtractionRunner.fieldsWithoutColumn(result, users));
    }
}
