package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyforge.cyberarkpoc.MockFixture;
import com.keyforge.cyberarkpoc.StubHttpServer;
import com.keyforge.cyberarkpoc.config.CyberArkConfig;
import com.keyforge.cyberarkpoc.config.PolicyConfig;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer.Fault;
import com.keyforge.cyberarkpoc.mock.SampleData;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Paging metadata, rate limiting, large and cut-off bodies, deadlines and temporary-file handling, against the mock and
 * stub servers (FABRICATED data; this proves our handling, not a real tenant's behaviour).
 */
class LargeResponseTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String SCRIPT = CloudApi.approverRoleScript("APP-CYA-ISPSS-SCA-AWS-%-BUApprovers");
    private static final String TOKEN_REPLY = "{\"access_token\":\"stub-token-abc\",\"expires_in\":900}";

    @TempDir
    Path spoolDir;

    private ResponseBody.Settings spool() {
        return new ResponseBody.Settings(spoolDir, ResponseBody.MEMORY_BYTES, 0, 0, Duration.ofHours(24));
    }

    private CloudApi stubApi(String root, Duration redrockTimeout) {
        return stubApi(root, URI.create(root + "/api/oauth2/platformtoken"), redrockTimeout);
    }

    private CloudApi stubApi(String apiRoot, URI tokenUrl, Duration redrockTimeout) {
        return new CloudApi(new CyberArkConfig(URI.create(apiRoot + "/api"), tokenUrl, "client", "secret-value",
                Duration.ofSeconds(30), CyberArkConfig.AuthMethod.PLATFORM, null, null, redrockTimeout), null)
                .withSpool(spool());
    }

    private static CloudApi mockApi(MockFixture f) {
        return new CloudApi(MockFixture.config(f.mock.rootUrl(), MockCyberArkServer.MOCK_CLIENT_SECRET), null);
    }

    private static CloudApi mockPolicies(MockFixture f, PolicyConfig.Api api) {
        return new CloudApi(null, MockFixture.policyConfig(f.mock.rootUrl(), api, MockCyberArkServer.MOCK_CLIENT_SECRET,
                50, 10));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> completeness(Map<String, Object> out) {
        return (Map<String, Object>) out.get("completeness");
    }

    private static StubHttpServer streaming(String path, IoWriter body) {
        return new StubHttpServer().reply("/api/oauth2/platformtoken", 200, TOKEN_REPLY).handle(path, ex -> {
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(200, 0);
            try (OutputStream o = new BufferedOutputStream(ex.getResponseBody(), 64 * 1024)) {
                body.write(o);
            }
        });
    }

    private interface IoWriter {
        void write(OutputStream out) throws IOException;
    }

    private static String sha(IoWriter body) throws IOException {
        LargeBodies.Digest d = new LargeBodies.Digest();
        body.write(d);
        return d.hex();
    }

    private static String shaOfResponse(Object response) throws IOException {
        LargeBodies.Digest d = new LargeBodies.Digest();
        MAPPER.writeValue(d, response);
        return d.hex();
    }

    private long filesLeft() throws IOException {
        try (var files = Files.list(spoolDir)) {
            return files.count();
        }
    }

    // ---- paging metadata: Redrock ------------------------------------------------------------

    @Test
    void redrockPagesSayWhetherMoreRowsMayExist() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            CloudApi api = mockApi(f);
            long total = ((Number) completeness(api.redrock(SCRIPT, 1, 1000, null, -1))
                    .get("records_in_response")).longValue();
            assertTrue(total >= 3, "the demo data has several approver roles");

            Map<String, Object> first = api.redrock(SCRIPT, 1, 2, null, -1);
            Map<String, Object> c1 = completeness(first);
            assertEquals(true, c1.get("response_complete"));
            assertEquals(2L, c1.get("records_in_response"));
            assertNull(c1.get("more_available"), "a full page cannot tell");
            assertNull(c1.get("all_records_in_this_response"));
            assertEquals(Map.of("pageNumber", 2, "pageSize", 2), c1.get("next_request"));

            int lastPage = (int) ((total + 1) / 2);
            Map<String, Object> last = completeness(api.redrock(SCRIPT, lastPage + (total % 2 == 0 ? 1 : 0), 2,
                    null, -1));
            assertEquals(false, last.get("more_available"));
            assertEquals(false, last.get("all_records_in_this_response"), "earlier pages hold the other rows");

            Map<String, Object> whole = completeness(api.redrock(SCRIPT, 1, 1000, null, -1));
            assertEquals(false, whole.get("more_available"));
            assertEquals(true, whole.get("all_records_in_this_response"), "a short first page holds everything");

            Map<String, Object> unpaged = completeness(api.redrock(SCRIPT, null, null, null, -1));
            assertNull(unpaged.get("more_available"), "no PageSize: CyberArk's default is undocumented");
            assertTrue(String.valueOf(unpaged.get("basis")).contains("default page size"));
        }
    }

    @Test
    void aShortPageThatContradictsFullCountIsFlagged() {
        String body = "{\"success\":true,\"Result\":{\"Count\":3,\"FullCount\":10,\"Results\":[{\"Row\":{\"ID\":\"a\"}},"
                + "{\"Row\":{\"ID\":\"b\"}},{\"Row\":{\"ID\":\"c\"}}]}}";
        try (StubHttpServer stub = new StubHttpServer().reply("/api/oauth2/platformtoken", 200, TOKEN_REPLY)
                .reply("/api/Redrock/query", 200, body)) {
            Map<String, Object> out = stubApi(stub.rootUrl(), null).redrock(SCRIPT, 1, 5, null, -1);
            Map<String, Object> c = completeness(out);
            assertEquals(true, out.get("ok"));
            assertEquals(3L, c.get("records_in_response"));
            assertNull(c.get("more_available"));
            assertEquals(false, c.get("all_records_in_this_response"));
            assertEquals(true, c.get("cyberark_limit_suspected"));
            assertEquals("10", ((JsonNode) ((Map<?, ?>) c.get("reported_by_cyberark")).get("FullCount")).asText());
        }
    }

    // ---- paging metadata: policies -----------------------------------------------------------

    @Test
    void uapContinuationEndsWithAnEmptyNextToken() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.POLICIES, Fault.EMPTY_FINAL_TOKEN);
            CloudApi api = mockPolicies(f, PolicyConfig.Api.UAP);
            String token = null;
            long seen = 0;
            Map<String, Object> c;
            int calls = 0;
            do {
                Map<String, Object> out = api.policies(3, token, null, null, null);
                assertEquals(true, out.get("ok"), String.valueOf(out));
                c = completeness(out);
                seen += (Long) c.get("records_in_response");
                Object next = c.get("next_request");
                token = next == null ? null : (String) ((Map<?, ?>) next).get("nextToken");
                assertTrue(++calls < 20);
            } while (Boolean.TRUE.equals(c.get("more_available")));
            assertEquals(false, c.get("more_available"));
            assertEquals(false, c.get("all_records_in_this_response"), "the last of several pages");
            assertTrue(String.valueOf(c.get("basis")).contains("an empty nextToken"));
            assertEquals(seen, ((JsonNode) ((Map<?, ?>) c.get("reported_by_cyberark")).get("total")).asLong());

            // The demo mock serves at most 3 per page whatever the limit (a server-side cap): the nextToken, not the
            // requested limit, decides whether more exist.
            Map<String, Object> capped = completeness(api.policies(50, null, null, null, null));
            assertEquals(3L, capped.get("records_in_response"));
            assertEquals(true, capped.get("more_available"));
            assertEquals(false, capped.get("all_records_in_this_response"));
        }
    }

    @Test
    void http429IsReportedWithRetryAfterAndNotRetried() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.POLICIES, Fault.HTTP_429);
            Map<String, Object> out = mockPolicies(f, PolicyConfig.Api.UAP).policies(2, null, null, null, null);

            assertEquals(false, out.get("ok"));
            assertEquals(429, out.get("http_status"));
            assertEquals("RATE_LIMITED", out.get("error_kind"));
            assertEquals("30", out.get("retry_after"));
            assertEquals("MOCK: injected too many requests",
                    ((ResponseBody) out.get("response")).tree().get("error").asText());
            assertEquals(1, f.mock.requestCount(MockCyberArkServer.POLICIES));
            assertNull(completeness(out).get("more_available"));
        }
    }

    @Test
    void scaParametersArePassedAndItsListIsUnpaged() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            Map<String, Object> out = mockPolicies(f, PolicyConfig.Api.SCA)
                    .policies(null, null, null, null, null, "aws", "MOCK HR", "1", "false");
            assertEquals(true, out.get("ok"), String.valueOf(out));
            assertTrue(((Map<?, ?>) out.get("request")).get("url").toString()
                    .endsWith("?cloud_provider=aws&free_text=MOCK%20HR&status=1&debug=false"));
            assertEquals(false, completeness(out).get("paged"));
            assertThrows(IllegalArgumentException.class, () -> mockPolicies(f, PolicyConfig.Api.UAP)
                    .policies(null, null, null, null, null, "aws", null, null, null));
        }
    }

    @Test
    void getRoleCountsPrincipalsAndPassesSuppressPrincipalsList() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            CloudApi api = mockApi(f);
            Map<String, Object> full = api.role("role-fin");
            long principals = ((ResponseBody) full.get("response")).tree().at("/Result/Principals").size();
            assertEquals(principals, completeness(full).get("records_in_response"));
            assertEquals(true, completeness(full).get("all_records_in_this_response"));

            Map<String, Object> suppressed = api.role("role-fin", true, false);
            assertTrue(((Map<?, ?>) suppressed.get("request")).get("url").toString()
                    .endsWith("?Name=role-fin&SuppressPrincipalsList=true&getRights=false"));
            assertTrue(((ResponseBody) suppressed.get("response")).tree().at("/Result/Principals").isMissingNode());
            assertNull(completeness(suppressed).get("records_in_response"));
        }
    }

    // ---- large bodies --------------------------------------------------------------------------

    @Test
    void aLargeRedrockPageIsReturnedByteForByteFromATemporaryFile() throws Exception {
        int rows = 200_000; // ~50 MB
        IoWriter body = o -> LargeBodies.redrock(o, rows);
        try (StubHttpServer stub = streaming("/api/Redrock/query", body)) {
            Map<String, Object> out = stubApi(stub.rootUrl(), null).redrock(SCRIPT, 1, rows + 1, null, -1);

            assertEquals(true, out.get("ok"), String.valueOf(out.get("error")));
            ResponseBody response = assertInstanceOf(ResponseBody.class, out.get("response"));
            assertTrue(response.spooled());
            assertEquals(1, filesLeft(), "kept in one temporary file until released");
            assertTrue((Long) out.get("response_bytes") > 40_000_000L);
            assertEquals(sha(body), shaOfResponse(response), "CyberArk's bytes unchanged");
            Map<String, Object> c = completeness(out);
            assertEquals((long) rows, c.get("records_in_response"));
            assertEquals(true, c.get("all_records_in_this_response"));

            ResponseBody.release(out);
            assertEquals(0, filesLeft());
        }
    }

    @Test
    void aVeryLargeSingleRecordIsCountedAndReturnedUnchanged() throws Exception {
        IoWriter body = o -> LargeBodies.role(o, 300_000, 30_000_000); // 300k principals and one 30 MB value
        try (StubHttpServer stub = streaming("/api/Roles/GetRole", body)) {
            Map<String, Object> out = stubApi(stub.rootUrl(), null).role("role-big");
            assertEquals(true, out.get("ok"), String.valueOf(out.get("error")));
            assertEquals(300_000L, completeness(out).get("records_in_response"));
            assertEquals(sha(body), shaOfResponse(out.get("response")));
            ResponseBody.release(out);
            assertEquals(0, filesLeft());
        }
    }

    @Test
    void ourSecretInALargeBodyIsMaskedAndTheUnmaskedFileIsDeleted() throws Exception {
        IoWriter body = o -> o.write(("{\"success\":true,\"Result\":{\"Results\":[],\"Echo\":\"x secret-value y\","
                + "\"Pad\":\"" + "p".repeat(3_000_000) + "\"}}").getBytes(StandardCharsets.UTF_8));
        try (StubHttpServer stub = streaming("/api/Redrock/query", body)) {
            Map<String, Object> out = stubApi(stub.rootUrl(), null).redrock(SCRIPT, 1, 10, null, -1);
            assertEquals(true, out.get("ok"));
            assertEquals(true, out.get("masked"));
            assertEquals(1, filesLeft(), "only the masked copy remains");
            String shown = MAPPER.writeValueAsString(out);
            assertFalse(shown.contains("secret-value"));
            assertTrue(shown.contains("\"Echo\":\"x *** y\""));
            ResponseBody.release(out);
            assertEquals(0, filesLeft());
        }
    }

    // ---- incomplete bodies ---------------------------------------------------------------------

    @Test
    void aSlowBodyIsStoppedAtTheDeadlineAndNothingIsReturned() throws Exception {
        try (StubHttpServer stub = new StubHttpServer().reply("/api/oauth2/platformtoken", 200, TOKEN_REPLY)
                .handle("/api/Redrock/query", ex -> {
                    ex.sendResponseHeaders(200, 0);
                    OutputStream o = ex.getResponseBody();
                    o.write("{\"success\":true,\"Result\":{\"Results\":[".getBytes(StandardCharsets.UTF_8));
                    o.write(new byte[0]);
                    for (int i = 0; i < 20; i++) {
                        o.write(("{\"Row\":{\"ID\":\"" + i + "\"}},").getBytes(StandardCharsets.UTF_8));
                        o.flush();
                        try {
                            Thread.sleep(300);
                        } catch (InterruptedException e) {
                            return;
                        }
                    }
                    o.write("{}]}}".getBytes(StandardCharsets.UTF_8));
                    o.close();
                })) {
            long start = System.nanoTime();
            Map<String, Object> out = stubApi(stub.rootUrl(), Duration.ofSeconds(1)).redrock(SCRIPT, 1, 100, null, -1);
            long ms = (System.nanoTime() - start) / 1_000_000;

            assertEquals(false, out.get("ok"));
            assertEquals("TRANSPORT", out.get("error_kind"));
            assertTrue(String.valueOf(out.get("error")).contains("did not arrive within 1 s"), String.valueOf(out));
            assertFalse(out.containsKey("response"), "no partial body");
            assertEquals(false, completeness(out).get("response_complete"));
            assertTrue((Long) completeness(out).get("received_bytes") > 0);
            assertTrue(ms < 3000, "stopped at the deadline, not after the whole body (" + ms + " ms)");
            assertFalse(Thread.currentThread().isInterrupted(), "no interrupt left on the caller's thread");
            assertEquals(0, filesLeft());
        }
    }

    @Test
    void bodiesCutOffMidWayAreTransportFailuresAndLeaveNoFile() throws Exception {
        String partial = "{\"success\":true,\"Result\":{\"Results\":[" + "{\"Row\":{\"ID\":\"x\"}},".repeat(100_000);
        String[] responses = {
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 5000000\r\n\r\n" + partial,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
                        + Integer.toHexString(partial.length()) + "\r\n" + partial + "\r\n"};
        for (String raw : responses) {
            try (StubHttpServer tokens = new StubHttpServer().reply("/oauth2/platformtoken", 200, TOKEN_REPLY);
                 LargeBodies.CutOffServer api = new LargeBodies.CutOffServer(raw)) {
                Map<String, Object> out = stubApi(api.rootUrl(), URI.create(tokens.rootUrl() + "/oauth2/platformtoken"),
                        null).redrock(SCRIPT, 1, 10, null, -1);

                assertEquals(false, out.get("ok"));
                assertEquals("TRANSPORT", out.get("error_kind"));
                assertTrue(String.valueOf(out.get("error")).contains("connection ended before the whole body"),
                        String.valueOf(out.get("error")));
                assertEquals(200, out.get("http_status"));
                assertFalse(out.containsKey("response"));
                assertEquals(false, completeness(out).get("response_complete"));
                assertEquals(0, filesLeft(), "the partial temporary file is deleted");
            }
        }
    }

    // ---- local protections and cleanup ---------------------------------------------------------

    @Test
    void theOptionalLocalLimitsAreExplicitErrorsNotTruncation() throws Exception {
        IoWriter body = o -> LargeBodies.redrock(o, 20_000); // ~5 MB
        try (StubHttpServer stub = streaming("/api/Redrock/query", body)) {
            CloudApi capped = stubApi(stub.rootUrl(), null).withSpool(
                    new ResponseBody.Settings(spoolDir, ResponseBody.MEMORY_BYTES, 2 * 1024 * 1024, 0,
                            Duration.ofHours(24)));
            Map<String, Object> out = capped.redrock(SCRIPT, 1, 50_000, null, -1);
            assertEquals(false, out.get("ok"));
            assertEquals("LOCAL_LIMIT", out.get("error_kind"));
            assertTrue(String.valueOf(out.get("error")).contains(ResponseBody.ENV_MAX_RESPONSE_MB));
            assertTrue(String.valueOf(out.get("error")).contains("not a CyberArk limit"));
            assertFalse(out.containsKey("response"));
            assertEquals(0, filesLeft());

            CloudApi noSpace = stubApi(stub.rootUrl(), null).withSpool(new ResponseBody.Settings(spoolDir,
                    ResponseBody.MEMORY_BYTES, 0, Long.MAX_VALUE / 4, Duration.ofHours(24)));
            Map<String, Object> out2 = noSpace.redrock(SCRIPT, 1, 50_000, null, -1);
            assertEquals("LOCAL_LIMIT", out2.get("error_kind"));
            assertTrue(String.valueOf(out2.get("error")).contains(ResponseBody.ENV_MIN_FREE_MB));
            assertEquals(0, filesLeft());
        }
    }

    @Test
    void filesLeftByACrashAreSweptButRecentOnesAreKept() throws Exception {
        Path old = Files.writeString(spoolDir.resolve(ResponseBody.FILE_PREFIX + "old" + ResponseBody.FILE_SUFFIX), "x");
        Path recent = Files.writeString(spoolDir.resolve(ResponseBody.FILE_PREFIX + "new" + ResponseBody.FILE_SUFFIX),
                "x");
        Path foreign = Files.writeString(spoolDir.resolve("someone-else.tmp"), "x");
        FileTime twoDaysAgo = FileTime.from(Instant.now().minus(Duration.ofDays(2)));
        Files.setLastModifiedTime(old, twoDaysAgo);
        Files.setLastModifiedTime(foreign, twoDaysAgo);

        assertEquals(1, ResponseBody.sweep(spool()));
        assertFalse(Files.exists(old));
        assertTrue(Files.exists(recent));
        assertTrue(Files.exists(foreign), "only our own files");
    }

    @Test
    void settingsComeFromTheEnvironment() {
        ResponseBody.Settings s = ResponseBody.Settings.fromEnvironment(Map.of(ResponseBody.ENV_DIR, "/tmp/x",
                ResponseBody.ENV_MAX_RESPONSE_MB, "100", ResponseBody.ENV_MIN_FREE_MB, "0"));
        assertEquals(Path.of("/tmp/x"), s.dir());
        assertEquals(100L * 1024 * 1024, s.maxBytes());
        assertEquals(0, s.minFreeBytes());
        ResponseBody.Settings d = ResponseBody.Settings.fromEnvironment(Map.of());
        assertEquals(0, d.maxBytes(), "no response-size limit by default");
        assertThrows(com.keyforge.cyberarkpoc.config.ConfigException.class,
                () -> ResponseBody.Settings.fromEnvironment(Map.of(ResponseBody.ENV_MAX_RESPONSE_MB, "-1")));
    }

    // ---- concurrency and memory ----------------------------------------------------------------

    @Test
    void concurrentLargeRequestsEachGetTheirOwnFileAndAllAreCleanedUp() throws Exception {
        int rows = 60_000; // ~14 MB each
        IoWriter body = o -> LargeBodies.redrock(o, rows);
        String expected = sha(body);
        try (StubHttpServer stub = streaming("/api/Redrock/query", body)) {
            ExecutorService pool = Executors.newFixedThreadPool(6);
            List<Future<Map<String, Object>>> calls = new ArrayList<>();
            for (int i = 0; i < 6; i++) {
                calls.add(pool.submit(() -> stubApi(stub.rootUrl(), null).redrock(SCRIPT, 1, rows + 1, null, -1)));
            }
            List<Map<String, Object>> results = new ArrayList<>();
            for (Future<Map<String, Object>> c : calls) {
                results.add(c.get(120, TimeUnit.SECONDS));
            }
            pool.shutdown();
            assertEquals(6, filesLeft(), "one file per response in flight");
            for (Map<String, Object> out : results) {
                assertEquals(true, out.get("ok"));
                assertEquals(expected, shaOfResponse(out.get("response")));
                ResponseBody.release(out);
            }
            assertEquals(0, filesLeft());
        }
    }

    @Test
    void memoryDoesNotGrowWithTheResponseSize() throws Exception {
        // 4 concurrent ~45 MB answers (~180 MB) received, checked and written out in a JVM limited to a 64 MB heap.
        Path dir = Files.createDirectory(spoolDir.resolve("probe"));
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        Process p = new ProcessBuilder(java, "-Xmx64m",
                "-Djdk.net.unixdomain.tmpdir=" + System.getProperty("jdk.net.unixdomain.tmpdir", spoolDir.toString()),
                "-cp", System.getProperty("java.class.path"), MemoryProbe.class.getName(), "180000", "4",
                dir.toString())
                .redirectErrorStream(true).start();
        String output;
        boolean finished = p.waitFor(180, TimeUnit.SECONDS);
        output = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!finished) {
            p.destroyForcibly();
        }
        System.out.println("[memory probe] " + output.trim());
        assertTrue(finished, "probe did not finish: " + output);
        assertEquals(0, p.exitValue(), output);
        assertTrue(output.contains("RESULT ok=4 threads=4"), output);
        assertTrue(output.contains("filesLeft=0"), output);
    }

    // ---- regression tests for the review findings -----------------------------------------------

    private Map<String, Object> redrockReply(String body, Integer pageNumber, Integer pageSize, Integer limit) {
        try (StubHttpServer stub = new StubHttpServer().reply("/api/oauth2/platformtoken", 200, TOKEN_REPLY)
                .reply("/api/Redrock/query", 200, body)) {
            return stubApi(stub.rootUrl(), null).redrock(SCRIPT, pageNumber, pageSize, limit, -1);
        }
    }

    private static String rows(int n, int fullCount) {
        return "{\"success\":true,\"Result\":{\"FullCount\":" + fullCount + ",\"Results\":["
                + String.join(",", java.util.Collections.nCopies(n, "{\"Row\":{\"ID\":\"x\"}}")) + "]}}";
    }

    @Test
    void twoJsonValuesInOneBodyAreNotJsonAndTheEnvelopeStaysValid() throws Exception {
        Map<String, Object> out = redrockReply("{\"success\":true,\"Result\":{\"Results\":[]}} {\"x\":1}", 1, 10, null);

        assertEquals(false, out.get("ok"));
        assertEquals("INVALID_RESPONSE", out.get("error_kind"));
        assertFalse(out.containsKey("response"));
        assertEquals("{\"success\":true,\"Result\":{\"Results\":[]}} {\"x\":1}", out.get("response_text"),
                "kept whole, as text");
        assertEquals(false, MAPPER.readTree(MAPPER.writeValueAsString(out)).isMissingNode(), "valid envelope");
        assertNull(completeness(out).get("records_in_response"));

        Map<String, Object> scalars = redrockReply("1 2", 1, 10, null);
        assertEquals("INVALID_RESPONSE", scalars.get("error_kind"));

        Map<String, Object> trailingSpace = redrockReply(rows(1, 1) + "\r\n  ", 1, 10, null);
        assertEquals(true, trailingSpace.get("ok"), "whitespace after the one value is fine");
    }

    @Test
    void aLimitBelowPageSizeNeverSuggestsANextPageThatCouldSkipRows() {
        Map<String, Object> full = completeness(redrockReply(rows(10, 100), 1, 100, 10));
        assertEquals(10L, full.get("records_in_response"));
        assertNull(full.get("more_available"));
        assertNull(full.get("next_request"), "pageNumber 2 with pageSize 100 would skip rows 11-100");
        assertTrue(String.valueOf(full.get("basis")).contains("could skip"));

        Map<String, Object> shortPage = completeness(redrockReply(rows(4, 4), 1, 100, 10));
        assertEquals(false, shortPage.get("more_available"), "fewer rows than the limit: the end either way");

        Map<String, Object> limitAbove = completeness(redrockReply(rows(10, 100), 1, 10, 50));
        assertEquals(Map.of("pageNumber", 2, "pageSize", 10, "limit", 50), limitAbove.get("next_request"),
                "a limit at or above pageSize cannot skip rows");
    }

    @Test
    void aLocalDiskFailureIsLocalStorageNotTransport() throws Exception {
        Path notADirectory = Files.writeString(spoolDir.resolve("a-file"), "x");
        IoWriter body = o -> LargeBodies.redrock(o, 20_000); // ~5 MB, so it must go to a temporary file
        try (StubHttpServer stub = streaming("/api/Redrock/query", body)) {
            Map<String, Object> out = stubApi(stub.rootUrl(), null).withSpool(new ResponseBody.Settings(notADirectory,
                    ResponseBody.MEMORY_BYTES, 0, 0, Duration.ofHours(24))).redrock(SCRIPT, 1, 50_000, null, -1);

            assertEquals(false, out.get("ok"));
            assertEquals("LOCAL_STORAGE", out.get("error_kind"));
            assertTrue(String.valueOf(out.get("error")).contains("temporary file"), String.valueOf(out.get("error")));
            assertTrue(String.valueOf(out.get("error")).contains("not a network or CyberArk failure"));
            assertEquals(200, out.get("http_status"));
            assertFalse(out.containsKey("response"));
            assertEquals(false, completeness(out).get("response_complete"));
        }
    }

    @Test
    void aTemporaryFileThatCannotBeReadIsAStorageErrorNotAConfigurationError() throws Exception {
        ResponseBody body;
        try (ResponseBody.Writer writer = new ResponseBody.Writer(spool())) {
            writer.write(new byte[2 * ResponseBody.MEMORY_BYTES]);
            body = writer.finish();
        }
        assertTrue(body.spooled());
        try (var files = Files.list(spoolDir)) {
            Files.delete(files.findFirst().orElseThrow()); // the file disappears underneath us
        }
        java.io.UncheckedIOException e = assertThrows(java.io.UncheckedIOException.class, body::text);
        assertInstanceOf(ResponseBody.LocalStorageException.class, e.getCause());
        assertThrows(java.io.UncheckedIOException.class, body::tree);
        assertThrows(ResponseBody.LocalStorageException.class, body::readText);

        Map<String, Object> run = com.keyforge.cyberarkpoc.rest.ExtractionRestServer.run("cloud/test",
                new com.keyforge.cyberarkpoc.rest.ExtractionRestServer.QueryRoute("test", p -> {
                    body.text();
                    return Map.of();
                }), Map.of());
        assertEquals("FAILED", run.get("status"));
        assertEquals("LOCAL_STORAGE", run.get("error_kind"));
        body.close();
        assertEquals(0, filesLeft());
    }

    @Test
    void staleFilesAreSweptPeriodicallyAndOnlyOurRegularFiles() throws Exception {
        Instant t0 = Instant.now();
        assertTrue(ResponseBody.maybeSweep(spool(), t0));

        FileTime twoDaysAgo = FileTime.from(t0.minus(Duration.ofDays(2)));
        Path stale = Files.writeString(spoolDir.resolve(ResponseBody.FILE_PREFIX + "crash" + ResponseBody.FILE_SUFFIX),
                "x");
        Path dirWithOurName = Files.createDirectory(spoolDir.resolve(ResponseBody.FILE_PREFIX + "dir"
                + ResponseBody.FILE_SUFFIX));
        Path nested = Files.createDirectory(spoolDir.resolve("sub"));
        Path nestedStale = Files.writeString(nested.resolve(ResponseBody.FILE_PREFIX + "n" + ResponseBody.FILE_SUFFIX),
                "x");
        for (Path p : new Path[] {stale, dirWithOurName, nestedStale}) {
            Files.setLastModifiedTime(p, twoDaysAgo);
        }

        assertFalse(ResponseBody.maybeSweep(spool(), t0.plus(Duration.ofMinutes(30))), "not again within the hour");
        assertTrue(Files.exists(stale));
        assertTrue(ResponseBody.maybeSweep(spool(), t0.plus(ResponseBody.SWEEP_EVERY)), "swept again later");
        assertFalse(Files.exists(stale), "a crash leftover is removed while the service keeps running");
        assertTrue(Files.exists(dirWithOurName), "directories are never deleted");
        assertTrue(Files.exists(nestedStale), "nothing below the configured directory");
    }

    @Test
    void anActiveFileIsNeverSwept() throws Exception {
        try (ResponseBody.Writer writer = new ResponseBody.Writer(new ResponseBody.Settings(spoolDir,
                ResponseBody.MEMORY_BYTES, 0, 0, Duration.ZERO))) { // everything counts as "old"
            writer.write(new byte[2 * ResponseBody.MEMORY_BYTES]);
            ResponseBody body = writer.finish();
            assertEquals(0, ResponseBody.sweep(new ResponseBody.Settings(spoolDir, ResponseBody.MEMORY_BYTES, 0, 0,
                    Duration.ZERO)));
            assertEquals(2L * ResponseBody.MEMORY_BYTES, body.readText().length(), "still readable");
            body.close();
        }
        assertEquals(0, filesLeft());
    }
}
