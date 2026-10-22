package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.config.PvwaConfig;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer.Fault;
import com.keyforge.cyberarkpoc.mock.SampleData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** PVWA session handling against the local mock (FABRICATED data). */
class PvwaClientTest {

    /** A clock the test can move forward. */
    static final class TestClock extends Clock {
        Instant now = Instant.parse("2026-10-22T10:00:00Z");

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    private MockCyberArkServer mock;
    private final TestClock clock = new TestClock();

    @BeforeEach
    void startMock() throws IOException {
        mock = MockCyberArkServer.start(SampleData.demo(), 0);
    }

    @AfterEach
    void stopMock() {
        mock.close();
    }

    private PvwaConfig config(String password) {
        return new PvwaConfig(URI.create(mock.rootUrl() + MockCyberArkServer.PVWA_APP), "CyberArk",
                MockCyberArkServer.MOCK_VAULT_USERNAME, password, Duration.ofSeconds(5), Duration.ofMinutes(18));
    }

    private PvwaClient client(String password) {
        return new PvwaClient(config(password), HttpClient.newHttpClient(), clock);
    }

    @Test
    void verifyLogsOnCallsAndLogsOff() {
        JsonNode verify;
        try (PvwaClient client = client(MockCyberArkServer.MOCK_VAULT_PASSWORD)) {
            verify = client.verify();
            assertEquals(1, client.logonCount());
            assertEquals(1, mock.openPvwaSessions());
        }
        assertEquals("MOCK Vault", verify.get("ServerName").asText());
        assertEquals("PasswordVault", verify.get("ApplicationName").asText());
        assertEquals(0, mock.openPvwaSessions(), "close() logged off");
        assertEquals(1, mock.requestCount(MockCyberArkServer.PVWA_LOGOFF));
    }

    @Test
    void wrongPasswordIsAnAuthenticationFailureAndLeavesNoSession() {
        try (PvwaClient client = client("wrong")) {
            CyberArkApiException e = assertThrows(CyberArkApiException.class, client::verify);
            assertEquals(CyberArkApiException.Kind.AUTHENTICATION, e.kind());
            assertEquals(401, e.httpStatus());
            assertTrue(!e.getMessage().contains("wrong"), "the password is never echoed");
        }
        assertEquals(0, mock.openPvwaSessions());
        assertEquals(0, mock.requestCount(MockCyberArkServer.PVWA_LOGOFF), "nothing to log off");
    }

    @Test
    void sessionIsReusedThenRenewedAfterItsAge() {
        try (PvwaClient client = client(MockCyberArkServer.MOCK_VAULT_PASSWORD)) {
            client.verify();
            client.verify();
            assertEquals(1, client.logonCount(), "same session within 18 minutes");

            clock.now = clock.now.plus(Duration.ofMinutes(19));
            client.verify();
            assertEquals(2, client.logonCount(), "renewed after 18 minutes");
            assertEquals(1, mock.requestCount(MockCyberArkServer.PVWA_LOGOFF), "old session logged off first");
        }
        assertEquals(0, mock.openPvwaSessions());
    }

    @Test
    void expiredSessionIsRenewedOnceOn401() {
        try (PvwaClient client = client(MockCyberArkServer.MOCK_VAULT_PASSWORD)) {
            client.verify();
            mock.expirePvwaSessions();

            assertEquals("MOCK Vault", client.verify().get("ServerName").asText());
            assertEquals(2, client.logonCount());
        }
    }

    @Test
    void persistent401IsAnAuthenticationFailure() {
        mock.fail(MockCyberArkServer.PVWA_VERIFY, Fault.HTTP_401);
        try (PvwaClient client = client(MockCyberArkServer.MOCK_VAULT_PASSWORD)) {
            CyberArkApiException e = assertThrows(CyberArkApiException.class, client::verify);
            assertEquals(CyberArkApiException.Kind.AUTHENTICATION, e.kind());
        }
        assertEquals(0, mock.openPvwaSessions(), "logged off even after failing");
    }

    @Test
    void serverErrorIsReported() {
        mock.fail(MockCyberArkServer.PVWA_VERIFY, Fault.HTTP_500);
        try (PvwaClient client = client(MockCyberArkServer.MOCK_VAULT_PASSWORD)) {
            CyberArkApiException e = assertThrows(CyberArkApiException.class, client::verify);
            assertEquals(CyberArkApiException.Kind.HTTP_STATUS, e.kind());
            assertEquals(500, e.httpStatus());
        }
    }

    @Test
    void onlyDocumentedReadPathsCanBeCalled() {
        try (PvwaClient client = client(MockCyberArkServer.MOCK_VAULT_PASSWORD)) {
            for (String forbidden : new String[] {
                    "/API/Accounts/12_3/Password/Retrieve/", "/API/Accounts/12_3/Verify/",
                    "/API/Accounts/12_3/Change/", "/API/Accounts/12_3/Reconcile/", "/API/Auth/Logoff/",
                    "/API/Safes/MySafe/", "/API/Users/5/"}) {
                assertThrows(IllegalArgumentException.class, () -> client.get(forbidden, Map.of()), forbidden);
            }
            assertEquals(0, client.logonCount(), "refused before any request, not even a logon");
        }
        assertTrue(PvwaClient.isAllowedReadPath("/API/Safes/"));
        assertTrue(PvwaClient.isAllowedReadPath("/API/Safes/BZ_I_87/Members/"));
        assertTrue(PvwaClient.isAllowedReadPath("/WebServices/PIMServices.svc/Accounts/12_3/Activities/"));
    }

    @Test
    void closeWithoutAnyCallDoesNothing() {
        PvwaClient client = client(MockCyberArkServer.MOCK_VAULT_PASSWORD);
        client.close();
        assertNull(client.logoffProblem());
        assertEquals(0, mock.requestCount(MockCyberArkServer.PVWA_LOGON));
    }
}
