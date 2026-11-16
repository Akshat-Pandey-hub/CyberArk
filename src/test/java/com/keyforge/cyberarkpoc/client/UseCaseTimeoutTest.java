package com.keyforge.cyberarkpoc.client;

import com.keyforge.cyberarkpoc.StubHttpServer;
import com.keyforge.cyberarkpoc.config.CyberArkConfig;
import com.keyforge.cyberarkpoc.config.PolicyConfig;
import com.sun.net.httpserver.HttpHandler;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Timeouts of the two use-case clients ({@link CyberArkClient} for Use Case 1, {@link PolicyClient} for Use Case 2)
 * against stub servers: Redrock gets its own timeout, every other call keeps the request timeout, and each response
 * must arrive in full (status, headers and body) within its timeout.
 */
class UseCaseTimeoutTest {

    private static final String TOKEN_REPLY = "{\"access_token\":\"stub-token-abc\",\"expires_in\":900}";
    private static final String ROWS = "{\"success\":true,\"Result\":{\"Count\":1,\"FullCount\":1,\"Results\":"
            + "[{\"Row\":{\"ID\":\"r1\",\"Name\":\"APP-1\",\"RoleType\":\"PrincipalList\"}}]}}";
    private static final String SECRET = "uc-secret-value-123";

    private static CyberArkClient identity(StubHttpServer stub, Duration requestTimeout, Duration redrockTimeout) {
        return new CyberArkClient(new CyberArkConfig(URI.create(stub.rootUrl() + "/api"),
                URI.create(stub.rootUrl() + "/oauth2/platformtoken"), "client", SECRET, requestTimeout,
                CyberArkConfig.AuthMethod.PLATFORM, null, null, redrockTimeout));
    }

    private static PolicyClient policies(StubHttpServer stub, Duration requestTimeout) {
        return new PolicyClient(new PolicyConfig(PolicyConfig.Api.UAP, URI.create(stub.rootUrl() + "/api"),
                URI.create(stub.rootUrl() + "/oauth2/token/app"), "client", SECRET, 50, 10, requestTimeout));
    }

    /** Waits {@code millis} before answering at all (status, headers and body). */
    private static HttpHandler lateAnswer(long millis, String body) {
        return ex -> {
            try {
                Thread.sleep(millis);
            } catch (InterruptedException e) {
                return;
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, bytes.length);
            try (OutputStream o = ex.getResponseBody()) {
                o.write(bytes);
            }
        };
    }

    /** Sends the status and headers at once, then the body a byte every 300 ms for about 6 s. */
    private static HttpHandler slowBody(String start) {
        return ex -> {
            ex.sendResponseHeaders(200, 0);
            OutputStream o = ex.getResponseBody();
            o.write(start.getBytes(StandardCharsets.UTF_8));
            o.flush();
            for (int i = 0; i < 20; i++) {
                try {
                    Thread.sleep(300);
                    o.write(' ');
                    o.flush();
                } catch (InterruptedException | IOException e) {
                    return;
                }
            }
            o.close();
        };
    }

    private static void assertStoppedAtTheDeadline(CyberArkApiException e, long ms, int seconds) {
        assertEquals(CyberArkApiException.Kind.TRANSPORT, e.kind());
        assertTrue(e.getMessage().contains("did not arrive within " + seconds + " s"), e.getMessage());
        assertTrue(ms < 3000, "stopped at the deadline, not after the whole body (" + ms + " ms)");
        assertFalse(Thread.currentThread().isInterrupted(), "no interrupt left on the caller's thread");
        assertFalse(e.getMessage().contains(SECRET));
    }

    @Test
    void useCase1RedrockCallsUseTheRedrockTimeout() {
        try (StubHttpServer stub = new StubHttpServer().reply("/oauth2/platformtoken", 200, TOKEN_REPLY)
                .handle("/api/Redrock/query", lateAnswer(2000, ROWS))) {
            CyberArkClient client = identity(stub, Duration.ofSeconds(1), Duration.ofSeconds(5));

            CyberArkClient.RoleSearch search = client.findRolesByNamePattern("APP-%", 1000, 10);

            assertEquals(1, search.roles().size(), "answered after 2 s: beyond the 1 s request timeout, within the "
                    + "5 s Redrock timeout");
            assertTrue(search.complete());
        }
    }

    @Test
    void useCase1OtherCallsKeepTheRequestTimeout() {
        try (StubHttpServer stub = new StubHttpServer().reply("/oauth2/platformtoken", 200, TOKEN_REPLY)
                .handle("/api/Roles/GetRole", lateAnswer(2000, "{\"success\":true,\"Result\":{}}"))
                .handle("/api/Roles/GetRoleMembers", lateAnswer(2000, ROWS))) {
            CyberArkClient client = identity(stub, Duration.ofSeconds(1), Duration.ofSeconds(5));

            CyberArkApiException role = assertThrows(CyberArkApiException.class, () -> client.getRole("r1"));
            assertEquals(CyberArkApiException.Kind.TRANSPORT, role.kind(), "GetRole keeps the 1 s request timeout");
            CyberArkApiException members = assertThrows(CyberArkApiException.class, () -> client.getRoleMembers("r1"));
            assertEquals(CyberArkApiException.Kind.TRANSPORT, members.kind(), "GetRoleMembers too");
        }
    }

    @Test
    void useCase1ABodyStillArrivingAtTheDeadlineIsATransportFailure() {
        try (StubHttpServer stub = new StubHttpServer().reply("/oauth2/platformtoken", 200, TOKEN_REPLY)
                .handle("/api/Redrock/query", slowBody("{\"success\":true,\"Result\":{\"Results\":["))
                .handle("/api/Roles/GetRole", slowBody("{\"success\":true,"))) {
            CyberArkClient client = identity(stub, Duration.ofSeconds(1), Duration.ofSeconds(1));

            long start = System.nanoTime();
            CyberArkApiException redrock = assertThrows(CyberArkApiException.class,
                    () -> client.findRolesByNamePattern("APP-%", 1000, 10));
            assertStoppedAtTheDeadline(redrock, (System.nanoTime() - start) / 1_000_000, 1);

            start = System.nanoTime();
            CyberArkApiException role = assertThrows(CyberArkApiException.class, () -> client.getRole("r1"));
            assertStoppedAtTheDeadline(role, (System.nanoTime() - start) / 1_000_000, 1);
        }
    }

    @Test
    void useCase2ABodyStillArrivingAtTheDeadlineIsATransportFailure() {
        try (StubHttpServer stub = new StubHttpServer().reply("/oauth2/token/app", 200, TOKEN_REPLY)
                .handle("/api/policies", slowBody("{\"results\":["))) {
            PolicyClient client = policies(stub, Duration.ofSeconds(1));

            long start = System.nanoTime();
            CyberArkApiException e = assertThrows(CyberArkApiException.class, client::listPolicies);
            assertStoppedAtTheDeadline(e, (System.nanoTime() - start) / 1_000_000, 1);
        }
    }

    @Test
    void aBodyCutOffMidWayIsATransportFailureForBothClients() throws Exception {
        String raw = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 5000\r\n\r\n"
                + "{\"results\":[{\"metadata\":{";
        try (StubHttpServer tokens = new StubHttpServer().reply("/oauth2/token/app", 200, TOKEN_REPLY)
                .reply("/oauth2/platformtoken", 200, TOKEN_REPLY);
             LargeBodies.CutOffServer api = new LargeBodies.CutOffServer(raw)) {
            PolicyClient policy = new PolicyClient(new PolicyConfig(PolicyConfig.Api.UAP,
                    URI.create(api.rootUrl() + "/api"), URI.create(tokens.rootUrl() + "/oauth2/token/app"), "client",
                    SECRET, 50, 10, Duration.ofSeconds(5)));
            CyberArkApiException p = assertThrows(CyberArkApiException.class, policy::listPolicies);
            assertEquals(CyberArkApiException.Kind.TRANSPORT, p.kind());
            assertTrue(p.getMessage().contains("connection ended before the whole response arrived"), p.getMessage());

            CyberArkClient identity = new CyberArkClient(new CyberArkConfig(URI.create(api.rootUrl() + "/api"),
                    URI.create(tokens.rootUrl() + "/oauth2/platformtoken"), "client", SECRET, Duration.ofSeconds(5),
                    CyberArkConfig.AuthMethod.PLATFORM, null, null, null));
            CyberArkApiException r = assertThrows(CyberArkApiException.class, () -> identity.getRole("r1"));
            assertEquals(CyberArkApiException.Kind.TRANSPORT, r.kind());
            assertTrue(r.getMessage().contains("connection ended before the whole response arrived"), r.getMessage());
        }
    }

    @Test
    void wholeResponsesArriveUnchanged() {
        String policyPage = "{\"results\":[{\"metadata\":{\"policyId\":\"p1\",\"name\":\"Ünïcödé policy\","
                + "\"status\":{\"status\":\"Active\"}}}],\"total\":1}";
        try (StubHttpServer stub = new StubHttpServer().reply("/oauth2/platformtoken", 200, TOKEN_REPLY)
                .reply("/oauth2/token/app", 200, TOKEN_REPLY)
                .reply("/api/Redrock/query", 200, ROWS)
                .reply("/api/policies", 200, policyPage)) {
            CyberArkClient.RoleSearch search = identity(stub, Duration.ofSeconds(5), Duration.ofSeconds(5))
                    .findRolesByNamePattern("APP-%", 1000, 10);
            assertEquals("APP-1", search.roles().get(0).name());

            PolicyClient.Listing listing = policies(stub, Duration.ofSeconds(5)).listPolicies();
            assertEquals(1, listing.policies().size());
            assertEquals("Ünïcödé policy", listing.policies().get(0).at("/metadata/name").asText(), "UTF-8 kept");
            assertTrue(listing.complete());
        }
    }
}
