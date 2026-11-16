package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.StubHttpServer;
import com.keyforge.cyberarkpoc.config.PvwaConfig;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PVWA reads under rate limiting, unavailable servers, network failures and slow bodies, against a stub server
 * (made-up answers; this proves our handling, not a real PVWA's behaviour).
 */
class PvwaClientRetryTest {

    private static final String APP = "/PasswordVault";
    private static final String SAFES = APP + "/API/Safes/";
    private static final String PAGE = "{\"value\":[{\"safeUrlId\":\"S1\",\"safeName\":\"S1\"}],\"count\":1}";

    /** A stub PVWA with Logon and Logoff; the test adds the Safes handler. */
    private static StubHttpServer pvwa() {
        return new StubHttpServer()
                .reply(APP + "/API/auth/Cyberark/Logon/", 200, "\"session-token-123\"")
                .reply(APP + "/API/Auth/Logoff/", 200, "");
    }

    private static PvwaClient client(StubHttpServer stub, Duration timeout, int retries) {
        return new PvwaClient(new PvwaConfig(URI.create(stub.rootUrl() + APP), "CyberArk", "svc-user",
                "vault-password-xyz", timeout, null, retries)).retryBaseDelay(Duration.ofMillis(10));
    }

    /** Answers with {@code status} for the first {@code failures} calls, then with the page. */
    private static com.sun.net.httpserver.HttpHandler failingThen(int failures, int status, String retryAfter,
                                                                  AtomicInteger calls) {
        return ex -> {
            int n = calls.incrementAndGet();
            byte[] body = (n <= failures ? "{\"ErrorMessage\":\"busy\"}" : PAGE).getBytes(StandardCharsets.UTF_8);
            if (n <= failures && retryAfter != null) {
                ex.getResponseHeaders().set("Retry-After", retryAfter);
            }
            ex.sendResponseHeaders(n <= failures ? status : 200, body.length);
            try (OutputStream o = ex.getResponseBody()) {
                o.write(body);
            }
        };
    }

    @Test
    void rateLimitAndUnavailableServerAreRetriedThenSucceed() {
        for (int status : new int[] {429, 502, 503, 504}) {
            AtomicInteger calls = new AtomicInteger();
            try (StubHttpServer stub = pvwa().handle(SAFES, failingThen(2, status, "0", calls));
                 PvwaClient client = client(stub, Duration.ofSeconds(5), 2)) {
                JsonNode page = client.get("/API/Safes/", Map.of());

                assertEquals("S1", page.get("value").get(0).get("safeUrlId").asText(), "HTTP " + status);
                assertEquals(3, calls.get(), "2 failures + 1 success for HTTP " + status);
                assertEquals(2, client.retryCount());
            }
        }
    }

    @Test
    void retriesAreBoundedAndTheLastAnswerIsReported() {
        AtomicInteger calls = new AtomicInteger();
        try (StubHttpServer stub = pvwa().handle(SAFES, failingThen(100, 429, "0", calls));
             PvwaClient client = client(stub, Duration.ofSeconds(5), 2)) {
            CyberArkApiException e = assertThrows(CyberArkApiException.class, () -> client.get("/API/Safes/", Map.of()));

            assertEquals(3, calls.get(), "the first try and 2 retries, never more");
            assertEquals(CyberArkApiException.Kind.HTTP_STATUS, e.kind());
            assertEquals(429, e.httpStatus());
            assertTrue(e.getMessage().contains("rate limited by PVWA (HTTP 429) (after 2 retries)"), e.getMessage());
        }
    }

    @Test
    void otherErrorsAreNotRetried() {
        for (int status : new int[] {500, 404, 400}) {
            AtomicInteger calls = new AtomicInteger();
            try (StubHttpServer stub = pvwa().handle(SAFES, failingThen(100, status, null, calls));
                 PvwaClient client = client(stub, Duration.ofSeconds(5), 2)) {
                CyberArkApiException e = assertThrows(CyberArkApiException.class,
                        () -> client.get("/API/Safes/", Map.of()));

                assertEquals(1, calls.get(), "HTTP " + status + " is not retried");
                assertEquals(status, e.httpStatus());
                assertEquals(0, client.retryCount());
            }
        }
    }

    @Test
    void zeroRetriesMeansOneTry() {
        AtomicInteger calls = new AtomicInteger();
        try (StubHttpServer stub = pvwa().handle(SAFES, failingThen(100, 503, "0", calls));
             PvwaClient client = client(stub, Duration.ofSeconds(5), 0)) {
            assertThrows(CyberArkApiException.class, () -> client.get("/API/Safes/", Map.of()));
            assertEquals(1, calls.get());
        }
    }

    @Test
    void aDroppedConnectionIsRetried() {
        AtomicInteger calls = new AtomicInteger();
        try (StubHttpServer stub = pvwa().handle(SAFES, ex -> {
            if (calls.incrementAndGet() <= 2) {
                ex.close(); // no status line at all: a network failure for the client
                return;
            }
            failingThen(0, 200, null, new AtomicInteger()).handle(ex);
        }); PvwaClient client = client(stub, Duration.ofSeconds(5), 2)) {
            JsonNode page = client.get("/API/Safes/", Map.of());

            assertEquals(1, page.get("count").asInt());
            assertEquals(3, calls.get());
            // Java's HttpClient itself may resend a GET once after a dropped connection; ours covers the rest
            assertTrue(client.retryCount() >= 1 && client.retryCount() <= 2, "retries: " + client.retryCount());
        }
    }

    @Test
    void aBodyStillArrivingAtTheTimeoutIsATransportFailure() {
        try (StubHttpServer stub = pvwa().handle(SAFES, ex -> {
            ex.sendResponseHeaders(200, 0); // headers at once, then the body slowly
            OutputStream o = ex.getResponseBody();
            o.write("{\"value\":[".getBytes(StandardCharsets.UTF_8));
            o.flush();
            for (int i = 0; i < 20; i++) {
                try {
                    Thread.sleep(300);
                    o.write(' ');
                    o.flush();
                } catch (InterruptedException | java.io.IOException e) {
                    return;
                }
            }
            o.write("],\"count\":0}".getBytes(StandardCharsets.UTF_8));
            o.close();
        }); PvwaClient client = client(stub, Duration.ofSeconds(1), 0)) {
            long start = System.nanoTime();
            CyberArkApiException e = assertThrows(CyberArkApiException.class, () -> client.get("/API/Safes/", Map.of()));
            long ms = (System.nanoTime() - start) / 1_000_000;

            assertEquals(CyberArkApiException.Kind.TRANSPORT, e.kind());
            assertTrue(e.getMessage().contains("did not arrive within 1 s"), e.getMessage());
            assertTrue(ms < 3000, "stopped at the timeout, not after the whole body (" + ms + " ms)");
            assertFalse(Thread.currentThread().isInterrupted(), "no interrupt left on the caller's thread");
        }
    }

    @Test
    void anExpiredSessionIsRenewedOnceWithoutCountingAsARetry() {
        AtomicInteger calls = new AtomicInteger();
        try (StubHttpServer stub = pvwa().handle(SAFES, failingThen(1, 401, null, calls));
             PvwaClient client = client(stub, Duration.ofSeconds(5), 2)) {
            client.get("/API/Safes/", Map.of());

            assertEquals(2, calls.get());
            assertEquals(2, client.logonCount(), "logged on again after the 401");
            assertEquals(0, client.retryCount());
        }
    }

    @Test
    void retrySettingIsValidatedAndReadFromTheEnvironment() {
        Map<String, String> env = Map.of(PvwaConfig.ENV_BASE_URL, "https://pvwa.example.com/PasswordVault",
                PvwaConfig.ENV_USERNAME, "u", PvwaConfig.ENV_PASSWORD, "p");
        assertEquals(PvwaConfig.DEFAULT_MAX_RETRIES, PvwaConfig.fromEnvironment(env).maxRetries());

        Map<String, String> five = new java.util.HashMap<>(env);
        five.put(PvwaConfig.ENV_MAX_RETRIES, "5");
        assertEquals(5, PvwaConfig.fromEnvironment(five).maxRetries());

        five.put(PvwaConfig.ENV_MAX_RETRIES, "11");
        assertThrows(com.keyforge.cyberarkpoc.config.ConfigException.class, () -> PvwaConfig.fromEnvironment(five));
        five.put(PvwaConfig.ENV_MAX_RETRIES, "x");
        assertThrows(com.keyforge.cyberarkpoc.config.ConfigException.class, () -> PvwaConfig.fromEnvironment(five));
    }
}
