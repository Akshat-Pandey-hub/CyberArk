package com.keyforge.cyberarkpoc.rest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer.Fault;
import com.keyforge.cyberarkpoc.mock.SampleData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The four cloud routes over HTTP, against the local mock (FABRICATED data). */
class CloudRoutesTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private MockCyberArkServer mock;
    private ExtractionRestServer rest;
    private final Map<String, String> env = new HashMap<>();

    @AfterEach
    void stop() {
        if (rest != null) {
            rest.stop();
        }
        if (mock != null) {
            mock.close();
        }
    }

    private void start() throws Exception {
        mock = MockCyberArkServer.start(SampleData.demo(), 0);
        env.put("CYBERARK_IDENTITY_BASE_URL", mock.rootUrl() + "/api");
        env.put("CYBERARK_TOKEN_URL", mock.rootUrl() + "/oauth2/platformtoken");
        env.put("CYBERARK_CLIENT_ID", MockCyberArkServer.MOCK_CLIENT_ID);
        env.put("CYBERARK_CLIENT_SECRET", MockCyberArkServer.MOCK_CLIENT_SECRET);
        env.put("CYBERARK_UAP_BASE_URL", mock.rootUrl() + "/api");
        env.put("CYBERARK_POLICY_TOKEN_URL", mock.rootUrl() + "/oauth2/token/" + MockCyberArkServer.MOCK_POLICY_APP_ID);
        rest = new ExtractionRestServer(new ExtractionRestServer.Settings("127.0.0.1", 0, "rest-user", "rest-pass"),
                () -> null, Map.of(), Map.of(), CloudRoutes.routes(() -> env));
        rest.start();
    }

    private HttpResponse<String> get(String pathAndQuery) throws Exception {
        return HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + rest.port()
                        + ExtractionRestServer.BASE_PATH + "/" + pathAndQuery))
                .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                        "rest-user:rest-pass".getBytes(StandardCharsets.UTF_8)))
                .GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void theFourRoutesAnswerWithCyberArksResponses() throws Exception {
        start();
        HttpResponse<String> token = get("cloud/token");
        HttpResponse<String> page1 = get("cloud/redrock?pageNumber=1&pageSize=2");
        String firstId = MAPPER.readTree(page1.body()).at("/response/Result/Results/0/Row/ID").asText();
        HttpResponse<String> role = get("cloud/role?id=" + firstId);
        HttpResponse<String> policies = get("cloud/policies?limit=2");
        String next = MAPPER.readTree(policies.body()).at("/response/nextToken").asText();
        HttpResponse<String> policies2 = get("cloud/policies?limit=2&nextToken="
                + URLEncoder.encode(next, StandardCharsets.UTF_8));

        for (HttpResponse<String> r : new HttpResponse[] {token, page1, role, policies, policies2}) {
            assertEquals(200, r.statusCode(), r.body());
            assertEquals("SUCCESS", r.headers().firstValue("X-KF-Run-Status").orElse(""));
            assertFalse(r.body().contains(MockCyberArkServer.MOCK_CLIENT_SECRET));
            assertFalse(r.body().contains("mock-token-"));
            assertFalse(r.body().contains("mock-policy-token-"));
        }
        assertEquals(2, MAPPER.readTree(page1.body()).at("/response/Result/Results").size());
        assertEquals(firstId, MAPPER.readTree(role.body()).at("/response/Result/Uuid").asText());
        JsonNode p1 = MAPPER.readTree(policies.body()).at("/response/results");
        JsonNode p2 = MAPPER.readTree(policies2.body()).at("/response/results");
        assertEquals(2, p1.size());
        assertEquals(2, p2.size());
        assertTrue(!p1.get(0).at("/metadata/policyId").equals(p2.get(0).at("/metadata/policyId")), "a new page");
    }

    @Test
    void routesAreListedAndBadParametersAre400() throws Exception {
        start();
        JsonNode routes = MAPPER.readTree(get("").body()).get("routes");
        for (String name : new String[] {"cloud/token", "cloud/redrock", "cloud/role", "cloud/policies"}) {
            assertTrue(routes.has(name), name);
        }
        HttpResponse<String> misspelt = get("cloud/redrock?pagesize=2");
        assertEquals(400, misspelt.statusCode());
        assertTrue(misspelt.body().contains("unknown parameter 'pagesize'"), misspelt.body());
        assertEquals(400, get("cloud/redrock?pageSize=abc").statusCode());
        assertEquals(400, get("cloud/policies?limit=51").statusCode());
        assertEquals(400, get("cloud/role").statusCode());
    }

    @Test
    void aCyberArkErrorIs502WithItsStatusAndBody() throws Exception {
        start();
        mock.fail(MockCyberArkServer.GET_ROLE, Fault.HTTP_403);
        HttpResponse<String> r = get("cloud/role?id=role-mkt");

        assertEquals(502, r.statusCode());
        JsonNode body = MAPPER.readTree(r.body());
        assertEquals(403, body.get("http_status").asInt());
        assertEquals("MOCK: injected forbidden", body.at("/response/error").asText());
    }

    @Test
    void missingSettingsAreAConfigurationError() throws Exception {
        start();
        env.remove("CYBERARK_CLIENT_SECRET");
        HttpResponse<String> r = get("cloud/redrock?pageNumber=1&pageSize=2");

        assertEquals(500, r.statusCode());
        assertEquals("CONFIG_ERROR", MAPPER.readTree(r.body()).get("status").asText());
        assertEquals(0, mock.requestCount(MockCyberArkServer.TOKEN));
    }

    @Test
    void theCallerChoosesTheRedrockQueryAndThePolicyParameters() throws Exception {
        start();
        String script = "SELECT ID, Username FROM User ORDER BY ID";
        HttpResponse<String> users = get("cloud/redrock?script=" + URLEncoder.encode(script, StandardCharsets.UTF_8)
                + "&pageNumber=1&pageSize=2");
        HttpResponse<String> policies = get("cloud/policies?limit=2&q=" + URLEncoder.encode("MOCK HR",
                StandardCharsets.UTF_8) + "&sort=createdBy");

        assertEquals(200, users.statusCode(), users.body());
        JsonNode body = MAPPER.readTree(users.body());
        assertEquals(script, body.at("/request/body/Script").asText());
        assertEquals(2, body.at("/response/Result/Results").size());
        body.at("/response/Result/Results").forEach(r -> assertEquals(2, r.get("Row").size(), "ID and Username only"));
        assertEquals(200, policies.statusCode(), policies.body());
        assertTrue(MAPPER.readTree(policies.body()).at("/request/url").asText().contains("q=MOCK%20HR&sort=createdBy"));
    }

    @Test
    void theDefaultQueryAndCachingComeFromSettings() throws Exception {
        start();
        env.put(CloudRoutes.ENV_REDROCK_SCRIPT, "SELECT Name FROM Role WHERE Name LIKE '%Finance%'");
        env.put(CloudRoutes.ENV_REDROCK_CACHING, "none");
        JsonNode configured = MAPPER.readTree(get("cloud/redrock").body());
        assertEquals("SELECT Name FROM Role WHERE Name LIKE '%Finance%'", configured.at("/request/body/Script").asText());
        assertTrue(configured.at("/request/body/args").isMissingNode(), "caching=none and no paging: no args");

        env.remove(CloudRoutes.ENV_REDROCK_SCRIPT);
        env.remove(CloudRoutes.ENV_REDROCK_CACHING);
        JsonNode fallback = MAPPER.readTree(get("cloud/redrock?pageNumber=1&pageSize=2").body());
        assertTrue(fallback.at("/request/body/Script").asText().contains("FROM Role WHERE Name LIKE "
                + "'APP-CYA-ISPSS-SCA-AWS-%-BUApprovers'"), "backward-compatible default");
        assertEquals(-1, fallback.at("/request/body/args/Caching").asInt());
    }
}
