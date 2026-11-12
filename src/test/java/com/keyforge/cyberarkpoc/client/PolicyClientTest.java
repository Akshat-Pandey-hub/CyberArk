package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.MockFixture;
import com.keyforge.cyberarkpoc.config.PolicyConfig.Api;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer.Fault;
import com.keyforge.cyberarkpoc.mock.SampleData;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Use Case 2 retrieval against the local mock (FABRICATED data): custom token, paging, completeness. */
class PolicyClientTest {

    private static List<String> ids(PolicyClient.Listing listing) {
        return listing.policies().stream().map(p -> p.path("metadata").path("policyId").asText()).toList();
    }

    private static boolean noteContains(PolicyClient.Listing listing, String text) {
        return listing.notes().stream().anyMatch(n -> n.contains(text));
    }

    @Test
    void uapPoliciesAreReadAcrossAllPagesAndMatchTheTotal() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            PolicyClient.Listing listing = f.policyClient(Api.UAP).listPolicies();

            assertEquals(List.of("pol-001", "pol-002", "pol-003", "pol-004", "pol-005", "pol-006", "pol-007",
                    "pol-008"), ids(listing));
            assertTrue(listing.complete(), listing.notes().toString());
            assertEquals(3, listing.pages());
            assertEquals(8, listing.reportedTotal());
            assertEquals(3, f.mock.requestCount(MockCyberArkServer.POLICIES));
        }
    }

    @Test
    void theCustomOAuth2TokenIsUsedOnceAndThePlatformTokenNever() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.policyClient(Api.UAP).listPolicies();

            assertEquals(1, f.mock.requestCount(MockCyberArkServer.POLICY_TOKEN), "one token for all 3 pages");
            assertEquals(0, f.mock.requestCount(MockCyberArkServer.TOKEN), "no platform token");
        }
    }

    @Test
    void thePolicyEndpointRejectsAPlatformToken() throws Exception {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            HttpClient http = HttpClient.newHttpClient();
            HttpResponse<String> token = http.send(HttpRequest.newBuilder(URI.create(f.mock.rootUrl()
                            + "/oauth2/platformtoken"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials&client_id="
                            + MockCyberArkServer.MOCK_CLIENT_ID + "&client_secret=" + MockCyberArkServer.MOCK_CLIENT_SECRET))
                    .build(), HttpResponse.BodyHandlers.ofString());
            String platformToken = Json.parse("t", 200, token.body()).get("access_token").asText();

            HttpResponse<String> policies = http.send(HttpRequest.newBuilder(URI.create(f.mock.rootUrl() + "/api/policies"))
                    .header("Authorization", "Bearer " + platformToken).GET().build(), HttpResponse.BodyHandlers.ofString());

            assertEquals(401, policies.statusCode());
        }
    }

    @Test
    void scaPoliciesAreReadInOneCallAndMatchTheTotal() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            PolicyClient.Listing listing = f.policyClient(Api.SCA).listPolicies();

            assertEquals(8, listing.policies().size());
            assertEquals("pol-002", listing.policies().get(1).get("policyId").asText());
            assertEquals(4, listing.policies().get(1).get("status").asInt());
            assertTrue(listing.complete());
            assertEquals(1, f.mock.requestCount(MockCyberArkServer.SCA_POLICIES));
        }
    }

    @Test
    void aRepeatedNextTokenStopsThePagingAsIncomplete() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.POLICIES, Fault.REPEAT_NEXT_TOKEN);
            PolicyClient.Listing listing = f.policyClient(Api.UAP).listPolicies();

            assertFalse(listing.complete());
            assertTrue(noteContains(listing, "nextToken repeated"), listing.notes().toString());
            assertEquals(2, listing.pages());
        }
    }

    @Test
    void aTotalThatDoesNotMatchIsIncomplete() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.POLICIES, Fault.WRONG_COUNT);
            PolicyClient.Listing uap = f.policyClient(Api.UAP).listPolicies();
            assertFalse(uap.complete());
            assertTrue(noteContains(uap, "reported total 9 but 8 policies were received"), uap.notes().toString());

            f.mock.fail(MockCyberArkServer.SCA_POLICIES, Fault.WRONG_COUNT);
            assertFalse(f.policyClient(Api.SCA).listPolicies().complete());
        }
    }

    @Test
    void aMissingTotalIsIncomplete() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.POLICIES, Fault.NO_TOTAL);
            PolicyClient.Listing listing = f.policyClient(Api.UAP).listPolicies();
            assertFalse(listing.complete());
            assertTrue(noteContains(listing, "no 'total'"));

            f.mock.fail(MockCyberArkServer.SCA_POLICIES, Fault.NO_TOTAL);
            assertFalse(f.policyClient(Api.SCA).listPolicies().complete());
        }
    }

    @Test
    void failedServicesMakeTheListIncomplete() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.POLICIES, Fault.FAILED_SERVICES);
            PolicyClient.Listing listing = f.policyClient(Api.UAP).listPolicies();

            assertFalse(listing.complete());
            assertTrue(noteContains(listing, "failedServices"));
        }
    }

    @Test
    void thePageLimitMakesTheListIncomplete() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            PolicyClient client = new PolicyClient(MockFixture.policyConfig(f.mock.rootUrl(), Api.UAP,
                    MockCyberArkServer.MOCK_CLIENT_SECRET, 50, 2));
            PolicyClient.Listing listing = client.listPolicies();

            assertFalse(listing.complete());
            assertEquals(2, listing.pages());
            assertTrue(noteContains(listing, "safety limit"));
        }
    }

    @Test
    void aWrongSecretIsAnAuthenticationFailureWithoutTheSecret() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            PolicyClient client = new PolicyClient(MockFixture.policyConfig(f.mock.rootUrl(), Api.UAP,
                    "wrong-secret-value", 50, 10));
            CyberArkApiException e = assertThrows(CyberArkApiException.class, client::listPolicies);

            assertEquals(CyberArkApiException.Kind.AUTHENTICATION, e.kind());
            assertEquals(401, e.httpStatus());
            assertEquals("policy-token", e.endpoint());
            assertFalse(client.sanitize(e.getMessage()).contains("wrong-secret-value"));
            assertEquals(0, f.mock.requestCount(MockCyberArkServer.POLICIES));
        }
    }

    @Test
    void aTokenEndpointErrorIsReported() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.POLICY_TOKEN, Fault.HTTP_500);
            CyberArkApiException e = assertThrows(CyberArkApiException.class, f.policyClient(Api.UAP)::listPolicies);

            assertEquals(CyberArkApiException.Kind.HTTP_STATUS, e.kind());
            assertEquals(500, e.httpStatus());
        }
    }

    @Test
    void aRevokedTokenIsRenewedOnce() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            PolicyClient client = f.policyClient(Api.UAP);
            client.listPolicies();
            f.mock.revokeTokens();

            assertEquals(8, client.listPolicies().policies().size());
            assertEquals(2, f.mock.requestCount(MockCyberArkServer.POLICY_TOKEN));
        }
    }

    @Test
    void persistent401And403AreAuthenticationFailures() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.POLICIES, Fault.HTTP_401);
            CyberArkApiException unauthorized = assertThrows(CyberArkApiException.class,
                    f.policyClient(Api.UAP)::listPolicies);
            assertEquals(CyberArkApiException.Kind.AUTHENTICATION, unauthorized.kind());
            assertEquals(401, unauthorized.httpStatus());

            f.mock.fail(MockCyberArkServer.SCA_POLICIES, Fault.HTTP_403);
            CyberArkApiException forbidden = assertThrows(CyberArkApiException.class,
                    f.policyClient(Api.SCA)::listPolicies);
            assertEquals(CyberArkApiException.Kind.AUTHENTICATION, forbidden.kind());
            assertEquals(403, forbidden.httpStatus());
        }
    }

    @Test
    void serverErrorsAndBrokenBodiesFailTheCall() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.POLICIES, Fault.HTTP_500);
            assertEquals(CyberArkApiException.Kind.HTTP_STATUS,
                    assertThrows(CyberArkApiException.class, f.policyClient(Api.UAP)::listPolicies).kind());

            f.mock.fail(MockCyberArkServer.POLICIES, Fault.MALFORMED_JSON);
            assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE,
                    assertThrows(CyberArkApiException.class, f.policyClient(Api.UAP)::listPolicies).kind());
        }
    }

    @Test
    void anUnreachableServerIsATransportFailure() {
        MockFixture f = MockFixture.start(SampleData.demo());
        PolicyClient client = f.policyClient(Api.UAP);
        f.close();
        assertEquals(CyberArkApiException.Kind.TRANSPORT,
                assertThrows(CyberArkApiException.class, client::listPolicies).kind());
    }

    @Test
    void sanitizeMasksTheSecretItsBasicFormAndIssuedTokens() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            PolicyClient client = f.policyClient(Api.UAP);
            client.listPolicies();
            String basic = java.util.Base64.getEncoder().encodeToString((MockCyberArkServer.MOCK_CLIENT_ID + ":"
                    + MockCyberArkServer.MOCK_CLIENT_SECRET).getBytes(java.nio.charset.StandardCharsets.UTF_8));

            String cleaned = client.sanitize("secret " + MockCyberArkServer.MOCK_CLIENT_SECRET + " basic " + basic);

            assertFalse(cleaned.contains(MockCyberArkServer.MOCK_CLIENT_SECRET));
            assertFalse(cleaned.contains(basic));
        }
    }

    @Test
    void recordsAreKeptWhole() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            JsonNode first = f.policyClient(Api.UAP).listPolicies().policies().get(0);

            assertEquals("Cloud Console", first.at("/metadata/policyEntitlement/targetCategory").asText());
            assertTrue(first.at("/metadata/updatedBy/user").isTextual(), "documented updatedBy, not updatedOn");
            assertTrue(first.has("principals"));
        }
    }
}
