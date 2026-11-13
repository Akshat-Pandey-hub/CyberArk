package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyforge.cyberarkpoc.MockFixture;
import com.keyforge.cyberarkpoc.StubHttpServer;
import com.keyforge.cyberarkpoc.config.CyberArkConfig;
import com.keyforge.cyberarkpoc.config.CyberArkConfig.AuthMethod;
import com.keyforge.cyberarkpoc.config.CyberArkConfig.TokenBody;
import com.keyforge.cyberarkpoc.config.PolicyConfig;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer.Fault;
import com.keyforge.cyberarkpoc.mock.SampleData;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The four cloud pass-through operations against the local mock (FABRICATED data) and a stub server. These prove the
 * requests we send and how we report answers; they do not prove what a real CyberArk tenant accepts.
 */
class CloudApiTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String PATTERN = "APP-CYA-ISPSS-SCA-AWS-%-BUApprovers";
    private static final String SCRIPT = CloudApi.approverRoleScript(PATTERN);

    private static CyberArkConfig identity(String root, AuthMethod method, String scope, TokenBody body,
                                           String secret, Duration redrockTimeout) {
        URI token = URI.create(root + (method == AuthMethod.PLATFORM ? "/oauth2/platformtoken"
                : "/oauth2/token/" + MockCyberArkServer.MOCK_IDENTITY_APP_ID));
        return new CyberArkConfig(URI.create(root + "/api"), token, MockCyberArkServer.MOCK_CLIENT_ID, secret,
                Duration.ofSeconds(5), method, scope, body, redrockTimeout);
    }

    private static CloudApi platform(MockFixture f) {
        return new CloudApi(identity(f.mock.rootUrl(), AuthMethod.PLATFORM, null, null,
                MockCyberArkServer.MOCK_CLIENT_SECRET, null), null);
    }

    private static CloudApi policies(MockFixture f) {
        return new CloudApi(null, MockFixture.policyConfig(f.mock.rootUrl(), PolicyConfig.Api.UAP,
                MockCyberArkServer.MOCK_CLIENT_SECRET, 50, 10));
    }

    private static JsonNode response(Map<String, Object> out) {
        Object body = out.get("response");
        return body instanceof ResponseBody raw ? raw.tree() : (JsonNode) body;
    }

    private static String json(Object value) throws Exception {
        return MAPPER.writeValueAsString(value);
    }

    private static List<String> roleIds(Map<String, Object> out) {
        List<String> ids = new ArrayList<>();
        response(out).at("/Result/Results").forEach(r -> ids.add(r.at("/Row/ID").asText()));
        return ids;
    }

    // ---- token -------------------------------------------------------------------------

    @Test
    void platformTokenSucceedsAndTheTokenIsNeverReturned() throws Exception {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            Map<String, Object> out = platform(f).token(CloudApi.Target.IDENTITY);

            assertEquals(true, out.get("ok"), json(out));
            assertEquals(200, out.get("http_status"));
            assertEquals("***", response(out).get("access_token").asText());
            assertEquals("Bearer", response(out).get("token_type").asText());
            assertEquals(3600, response(out).get("expires_in").asInt());
            assertFalse(json(out).contains("mock-token-"));
            assertFalse(json(out).contains(MockCyberArkServer.MOCK_CLIENT_SECRET));
        }
    }

    @Test
    void oauth2AppTokenIsRequestedWithBasicAuthAndAFormBodyWithTheScope() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            CloudApi api = new CloudApi(identity(f.mock.rootUrl(), AuthMethod.OAUTH2_APP, "reporting", TokenBody.FORM,
                    MockCyberArkServer.MOCK_CLIENT_SECRET, null), null);

            assertEquals(true, api.token(CloudApi.Target.IDENTITY).get("ok"));
            assertEquals(List.of("application/x-www-form-urlencoded | grant_type=client_credentials&scope=reporting"),
                    f.mock.appTokenRequests());
            assertEquals(true, api.redrock(SCRIPT, 1, 2, null, -1).get("ok"), "the app token is used for Redrock");
        }
    }

    @Test
    void oauth2AppTokenCanUseTheJsonBodyOfTheScaReference() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            Map<String, Object> out = policies(f).token(CloudApi.Target.POLICIES);

            assertEquals(true, out.get("ok"));
            assertEquals(List.of("application/json | {\"grant_type\":\"client_credentials\"}"),
                    f.mock.appTokenRequests());
        }
    }

    @Test
    void aRejectedLoginShowsCyberArksOwnErrorButNeverTheSecret() throws Exception {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            CloudApi api = new CloudApi(identity(f.mock.rootUrl(), AuthMethod.OAUTH2_APP, null, TokenBody.FORM,
                    "wrong-secret-value", null), null);

            for (Map<String, Object> out : List.of(api.token(CloudApi.Target.IDENTITY), api.redrock(SCRIPT, 1, 2, null, -1))) {
                assertEquals(false, out.get("ok"));
                assertEquals("token", out.get("stage"));
                assertEquals(401, out.get("http_status"));
                assertEquals("AUTHENTICATION", out.get("error_kind"));
                assertEquals("invalid_client", response(out).get("error").asText());
                assertEquals("MOCK: client authentication failed", response(out).get("error_description").asText());
                assertTrue(String.valueOf(out.get("error")).contains("client authentication failed"), json(out));
                assertFalse(json(out).contains("wrong-secret-value"));
            }
        }
    }

    // ---- redrock -----------------------------------------------------------------------

    @Test
    void redrockPagesAreRequestedSeparatelyWithoutLimitAndDoNotOverlap() throws Exception {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            CloudApi api = platform(f);
            Map<String, Object> page1 = api.redrock(SCRIPT, 1, 2, null, -1);
            Map<String, Object> page2 = api.redrock(SCRIPT, 2, 2, null, -1);
            Map<String, Object> page3 = api.redrock(SCRIPT, 3, 2, null, -1);

            assertEquals(true, page1.get("ok"), json(page1));
            assertEquals(2, roleIds(page1).size());
            assertEquals(2, roleIds(page2).size());
            assertEquals(1, roleIds(page3).size(), "5 matching roles: 2 + 2 + 1");
            Set<String> all = new HashSet<>(roleIds(page1));
            all.addAll(roleIds(page2));
            all.addAll(roleIds(page3));
            assertEquals(5, all.size(), "no role appears on two pages");
            for (String body : f.mock.redrockBodies()) {
                JsonNode args = MAPPER.readTree(body).get("args");
                assertEquals(Set.of("PageNumber", "PageSize", "Caching"), fieldNames(args), "no Limit unless asked");
            }
            assertEquals(2, MAPPER.readTree(f.mock.redrockBodies().get(1)).at("/args/PageNumber").asInt());
            assertEquals(5, response(page1).at("/Result/FullCount").asInt(), "CyberArk's fields are passed through");
        }
    }

    @Test
    void redrockSendsLimitOnlyWhenGivenAndEachArgumentOnItsOwn() throws Exception {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            CloudApi api = platform(f);
            api.redrock(SCRIPT, null, 3, 7, -1);
            api.redrock(SCRIPT, 2, null, null, -1);

            JsonNode first = MAPPER.readTree(f.mock.redrockBodies().get(0)).get("args");
            JsonNode second = MAPPER.readTree(f.mock.redrockBodies().get(1)).get("args");
            assertEquals(Set.of("PageSize", "Limit", "Caching"), fieldNames(first));
            assertEquals(7, first.get("Limit").asInt());
            assertEquals(Set.of("PageNumber", "Caching"), fieldNames(second));
            assertThrows(IllegalArgumentException.class, () -> api.redrock(SCRIPT, 1, 0, null, -1));
        }
    }

    @Test
    void redrockSuccessFalseIsNeverReportedAsSuccess() throws Exception {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.REDROCK_ROLE, Fault.SUCCESS_FALSE);
            Map<String, Object> out = platform(f).redrock(SCRIPT, 1, 2, null, -1);

            assertEquals(false, out.get("ok"));
            assertEquals(200, out.get("http_status"));
            assertEquals("API_FAILURE", out.get("error_kind"));
            assertFalse(response(out).get("success").asBoolean(), "CyberArk's body is kept");
        }
    }

    @Test
    void aSlowAnswerIsATimeoutNotAnEmptyResult() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.REDROCK_ROLE, Fault.DELAY);
            CloudApi api = new CloudApi(identity(f.mock.rootUrl(), AuthMethod.PLATFORM, null, null,
                    MockCyberArkServer.MOCK_CLIENT_SECRET, Duration.ofSeconds(1)), null);
            Map<String, Object> out = api.redrock(SCRIPT, 1, 2, null, -1);

            assertEquals(false, out.get("ok"));
            assertEquals("TRANSPORT", out.get("error_kind"));
            assertTrue(String.valueOf(out.get("error")).contains("HttpTimeoutException"), String.valueOf(out));
            assertNull(out.get("http_status"));
        }
    }

    // ---- role --------------------------------------------------------------------------

    @Test
    void getRoleReturnsCyberArksBodyWithTheDocumentedTypedPrincipals() throws Exception {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            Map<String, Object> out = platform(f).role("role-mkt");

            assertEquals(true, out.get("ok"), json(out));
            assertEquals("role-mkt", response(out).at("/Result/Uuid").asText());
            assertEquals("POST", ((Map<?, ?>) out.get("request")).get("method"));
            assertTrue(String.valueOf(((Map<?, ?>) out.get("request")).get("url")).endsWith("/Roles/GetRole?Name=role-mkt"));
            response(out).at("/Result/Principals").forEach(p -> assertTrue(p.asText().matches("[ugr]=.+"), p.asText()));
        }
    }

    @Test
    void a403IsReturnedWithItsBodyAndNotRetried() throws Exception {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.GET_ROLE, Fault.HTTP_403);
            Map<String, Object> out = platform(f).role("role-mkt");

            assertEquals(false, out.get("ok"));
            assertEquals(403, out.get("http_status"));
            assertEquals("AUTHORIZATION", out.get("error_kind"));
            assertEquals("MOCK: injected forbidden", response(out).get("error").asText());
            assertEquals(1, f.mock.requestCount(MockCyberArkServer.GET_ROLE), "no retry on 403");
            assertEquals(1, f.mock.requestCount(MockCyberArkServer.TOKEN));
        }
    }

    @Test
    void a401RenewsTheTokenAndRetriesExactlyOnce() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            CloudApi api = platform(f);
            api.role("role-mkt");
            f.mock.revokeTokens();

            Map<String, Object> renewed = api.role("role-mkt");
            assertEquals(true, renewed.get("ok"));
            assertEquals(true, renewed.get("retried_after_401"));
            assertEquals(2, f.mock.requestCount(MockCyberArkServer.TOKEN));

            f.mock.fail(MockCyberArkServer.GET_ROLE, Fault.HTTP_401);
            int before = f.mock.requestCount(MockCyberArkServer.GET_ROLE);
            Map<String, Object> rejected = api.role("role-mkt");
            assertEquals(false, rejected.get("ok"));
            assertEquals(401, rejected.get("http_status"));
            assertEquals(2, f.mock.requestCount(MockCyberArkServer.GET_ROLE) - before, "one retry, then stop");
        }
    }

    // ---- policies ----------------------------------------------------------------------

    @Test
    void policiesFollowCyberArksNextTokenOnePageAtATime() throws Exception {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            CloudApi api = policies(f);
            List<String> ids = new ArrayList<>();
            String nextToken = null;
            int calls = 0;
            do {
                Map<String, Object> out = api.policies(2, nextToken, null, null, null);
                calls++;
                assertEquals(true, out.get("ok"), json(out));
                String url = String.valueOf(((Map<?, ?>) out.get("request")).get("url"));
                assertTrue(url.contains("limit=2"), url);
                response(out).get("results").forEach(p -> ids.add(p.at("/metadata/policyId").asText()));
                assertEquals(8, response(out).get("total").asInt());
                JsonNode token = response(out).get("nextToken");
                nextToken = token == null || token.isNull() ? null : token.asText();
            } while (nextToken != null && calls < 10);

            assertEquals(4, calls, "8 policies, 2 per call");
            assertEquals(8, new HashSet<>(ids).size(), "every policy once");
            assertEquals(4, f.mock.requestCount(MockCyberArkServer.POLICIES), "one request per call, no hidden loop");
        }
    }

    @Test
    void policyLimitOutsideTheDocumentedRangeIsRejectedBeforeAnyCall() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            assertThrows(IllegalArgumentException.class, () -> policies(f).policies(51, null, null, null, null));
            assertThrows(IllegalArgumentException.class, () -> policies(f).policies(0, null, null, null, null));
            assertEquals(0, f.mock.requestCount(MockCyberArkServer.POLICY_TOKEN));
        }
    }

    @Test
    void aBodyThatIsNotJsonIsReturnedAsTextAndMarkedInvalid() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.POLICIES, Fault.MALFORMED_JSON);
            Map<String, Object> out = policies(f).policies(2, null, null, null, null);

            assertEquals(false, out.get("ok"));
            assertEquals("INVALID_RESPONSE", out.get("error_kind"));
            assertEquals("{ this is not json", out.get("response_text"));
        }
    }

    @Test
    void anUnreachableServerIsATransportFailure() {
        MockFixture f = MockFixture.start(SampleData.demo());
        CloudApi api = policies(f);
        f.close();
        Map<String, Object> out = api.policies(2, null, null, null, null);
        assertEquals(false, out.get("ok"));
        assertEquals("TRANSPORT", out.get("error_kind"));
        assertEquals("token", out.get("stage"));
    }

    // ---- exact preservation (stub server) -------------------------------------------------

    @Test
    void cyberArksBodyIsReturnedUnchangedExceptOurOwnSecrets() throws Exception {
        String secret = "stub-secret-123";
        String body = "{\"success\":true,\"Result\":{\"Count\":2,\"Ratio\":1.10,\"Big\":12345678901234567890,"
                + "\"Zeta\":{\"z\":1},\"Alpha\":[null,\"x\"],\"Unknown\":{\"nested\":{\"deep\":true}},"
                + "\"Echo\":\"secret=" + secret + "\",\"Results\":[]}}";
        try (StubHttpServer stub = new StubHttpServer()
                .reply("/api/oauth2/platformtoken", 200, "{\"access_token\":\"stub-token-abc\",\"expires_in\":900}")
                .reply("/api/Redrock/query", 200, body)) {
            CloudApi api = new CloudApi(new CyberArkConfig(URI.create(stub.rootUrl() + "/api"), null, "client", secret,
                    Duration.ofSeconds(5)), null);
            Map<String, Object> out = api.redrock(SCRIPT, 1, 2, null, -1);

            assertEquals(true, out.get("ok"));
            assertEquals(true, out.get("masked"));
            String shown = json(out.get("response"));
            assertEquals(body.replace(secret, "***"), shown, "same fields, order and number text");
            assertFalse(json(out).contains("stub-token-abc"));
        }
    }

    @Test
    void aBodyWithDuplicateKeysIsKeptWhole() {
        String body = "{\"success\":true,\"Result\":{\"Results\":[],\"Count\":1,\"Count\":2}}";
        try (StubHttpServer stub = new StubHttpServer()
                .reply("/api/oauth2/platformtoken", 200, "{\"access_token\":\"stub-token-abc\",\"expires_in\":900}")
                .reply("/api/Redrock/query", 200, body)) {
            CloudApi api = new CloudApi(new CyberArkConfig(URI.create(stub.rootUrl() + "/api"), null, "client",
                    "secret-value", Duration.ofSeconds(5)), null);
            Map<String, Object> out = api.redrock(SCRIPT, 1, 2, null, -1);

            assertEquals(true, out.get("ok"));
            assertEquals(true, out.get("duplicate_keys"));
            assertEquals(body, out.get("response_text"), "both values kept, as text");
        }
    }

    @Test
    void aServerErrorBodyIsPreserved() {
        String error = "{\"code\":\"UAP9999\",\"message\":\"General Error\",\"description\":\"General Error\"}";
        try (StubHttpServer stub = new StubHttpServer()
                .reply("/oauth2/token/app", 200, "{\"access_token\":\"stub-token-abc\",\"expires_in\":900}")
                .reply("/api/policies", 500, error)) {
            CloudApi api = new CloudApi(null, new PolicyConfig(PolicyConfig.Api.UAP, URI.create(stub.rootUrl() + "/api"),
                    URI.create(stub.rootUrl() + "/oauth2/token/app"), "client", "secret-value", 50, 10,
                    Duration.ofSeconds(5)));
            Map<String, Object> out = api.policies(null, null, null, null, null);

            assertEquals(false, out.get("ok"));
            assertEquals(500, out.get("http_status"));
            assertEquals("HTTP_STATUS", out.get("error_kind"));
            assertEquals("UAP9999", response(out).get("code").asText());
            assertEquals(stub.rootUrl() + "/api/policies", ((Map<?, ?>) out.get("request")).get("url"),
                    "no limit or nextToken unless given");
        }
    }

    // ---- any query, any parameter: no Java change needed --------------------------------

    private static List<Set<String>> rowColumns(Map<String, Object> out) {
        List<Set<String>> columns = new ArrayList<>();
        response(out).at("/Result/Results").forEach(r -> columns.add(fieldNames(r.get("Row"))));
        return columns;
    }

    @Test
    void anyRedrockQueryIsSentVerbatimAndItsColumnsComeBack() throws Exception {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            CloudApi api = platform(f);
            String q1 = "SELECT ID, Name FROM Role WHERE Name LIKE 'APP-CYA-%' ORDER BY ID";
            String q2 = "select Name, RoleType from Role where Name like '%AWS-Finance%'";
            String q3 = "SELECT ID, Username, StatusEnum FROM User ORDER BY ID";
            String q4 = "SELECT * FROM Role WHERE Name LIKE '%-BUApprovers'";

            Map<String, Object> r1 = api.redrock(q1, null, null, null, null);
            Map<String, Object> r2 = api.redrock(q2, null, null, null, null);
            Map<String, Object> r3 = api.redrock(q3, 1, 3, null, -1);
            Map<String, Object> r3b = api.redrock(q3, 2, 3, null, -1);
            Map<String, Object> r4 = api.redrock(q4, null, null, null, null);

            for (Map<String, Object> out : List.of(r1, r2, r3, r3b, r4)) {
                assertEquals(true, out.get("ok"), json(out));
            }
            List<String> sent = new ArrayList<>();
            for (String body : f.mock.redrockBodies()) {
                sent.add(MAPPER.readTree(body).get("Script").asText());
            }
            assertEquals(List.of(q1, q2, q3, q3, q4), sent, "each script exactly as given");
            rowColumns(r1).forEach(c -> assertEquals(Set.of("ID", "Name"), c));
            rowColumns(r2).forEach(c -> assertEquals(Set.of("Name", "RoleType"), c));
            assertEquals(1, rowColumns(r2).size(), "CyberArk's (here the mock's) filter, not ours");
            rowColumns(r3).forEach(c -> assertEquals(Set.of("ID", "Username", "StatusEnum"), c));
            assertEquals(3, rowColumns(r3).size(), "the User table, page 1 of size 3");
            Set<String> page1 = new HashSet<>();
            response(r3).at("/Result/Results").forEach(r -> page1.add(r.at("/Row/ID").asText()));
            response(r3b).at("/Result/Results").forEach(r -> assertFalse(page1.contains(r.at("/Row/ID").asText())));
            rowColumns(r4).forEach(c -> assertEquals(Set.of("ID", "Name", "RoleType", "ReadOnly", "Description"), c));
        }
    }

    @Test
    void aQueryCyberArkRejectsReturnsItsOwnMessage() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            Map<String, Object> out = platform(f).redrock("SELECT Nope FROM Role WHERE Name LIKE '%'", null, null,
                    null, null);

            assertEquals(false, out.get("ok"));
            assertEquals("API_FAILURE", out.get("error_kind"));
            assertEquals("Query has failed: no such column: Nope", response(out).get("Message").asText());
        }
    }

    @Test
    void redrockArgsAreSentOnlyWhenGivenIncludingCaching() throws Exception {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            CloudApi api = platform(f);
            api.redrock(SCRIPT, null, null, null, null);
            api.redrock(SCRIPT, null, null, null, 0);

            assertFalse(MAPPER.readTree(f.mock.redrockBodies().get(0)).has("args"), "nothing given, no args sent");
            JsonNode args = MAPPER.readTree(f.mock.redrockBodies().get(1)).get("args");
            assertEquals(Set.of("Caching"), fieldNames(args));
            assertEquals(0, args.get("Caching").asInt());
            assertThrows(IllegalArgumentException.class, () -> api.redrock(" ", 1, 2, null, -1));
        }
    }

    @Test
    void documentedUapParametersArePassedThroughEncodedAndOnlyWhenGiven() throws Exception {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            CloudApi api = policies(f);
            String filter = "((status eq 'Error') or (status eq 'Warning')) and (targetCategory eq 'Cloud Console')";
            String q = "access to production";
            Map<String, Object> out = api.policies(2, null, filter, q, "createdBy");
            api.policies(null, null, null, null, null);
            api.policies(2, "DS1_10;DS2_20", null, null, null); // the documented multi-source token format

            assertEquals(true, out.get("ok"), json(out));
            String raw = f.mock.policyQueries().get(0);
            assertFalse(raw.contains("+"), "spaces are sent as %20: " + raw);
            Map<String, String> received = ExtractionParams.decode(raw);
            assertEquals(Set.of("limit", "filter", "q", "sort"), received.keySet());
            assertEquals("2", received.get("limit"));
            assertEquals(filter, received.get("filter"));
            assertEquals(q, received.get("q"));
            assertEquals("createdBy", received.get("sort"));
            assertEquals("null", f.mock.policyQueries().get(1), "nothing given, no query string at all");
            assertEquals("DS1_10;DS2_20", ExtractionParams.decode(f.mock.policyQueries().get(2)).get("nextToken"),
                    "the token arrives unchanged");
        }
    }

    @Test
    void theScaPolicyApiDoesNotAcceptUapParameters() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            CloudApi api = new CloudApi(null, MockFixture.policyConfig(f.mock.rootUrl(), PolicyConfig.Api.SCA,
                    MockCyberArkServer.MOCK_CLIENT_SECRET, 50, 10));
            assertThrows(IllegalArgumentException.class, () -> api.policies(null, null, "x", null, null));
            assertEquals(true, api.policies(null, null, null, null, null).get("ok"));
        }
    }

    /** Decodes a raw query string the way a server does (percent-decoding; values may contain ';'). */
    private static final class ExtractionParams {
        static Map<String, String> decode(String raw) {
            Map<String, String> out = new java.util.LinkedHashMap<>();
            for (String pair : raw.split("&")) {
                int eq = pair.indexOf('=');
                out.put(java.net.URLDecoder.decode(pair.substring(0, eq), java.nio.charset.StandardCharsets.UTF_8),
                        java.net.URLDecoder.decode(pair.substring(eq + 1), java.nio.charset.StandardCharsets.UTF_8));
            }
            return out;
        }
    }

    private static Set<String> fieldNames(JsonNode node) {
        Set<String> names = new HashSet<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }
}
