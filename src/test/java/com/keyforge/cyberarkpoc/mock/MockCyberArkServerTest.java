package com.keyforge.cyberarkpoc.mock;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The mock labels every response as fabricated and enforces the bearer token. */
class MockCyberArkServerTest {

    @Test
    void everyResponseIsLabelledAsFabricated() throws Exception {
        try (MockCyberArkServer mock = MockCyberArkServer.start(SampleData.demo(), 0)) {
            HttpResponse<String> response = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(URI.create(mock.rootUrl() + "/api/policies")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());

            assertEquals(401, response.statusCode(), "no token, so unauthorized");
            assertTrue(response.headers().firstValue(MockCyberArkServer.MOCK_HEADER).orElse("").startsWith("FABRICATED"));
            assertTrue(response.body().contains(MockCyberArkServer.MOCK_FIELD));
        }
    }

    @Test
    void likePatternMatchesLikeSql() {
        assertTrue(MockCyberArkServer.likeToRegex("APP-%-X").matcher("app-anything-x").matches());
        assertTrue(MockCyberArkServer.likeToRegex("A_C").matcher("ABC").matches());
        assertFalse(MockCyberArkServer.likeToRegex("A_C").matcher("ABBC").matches());
        assertFalse(MockCyberArkServer.likeToRegex("A.C").matcher("ABC").matches(), "dots are literal");
    }
}
