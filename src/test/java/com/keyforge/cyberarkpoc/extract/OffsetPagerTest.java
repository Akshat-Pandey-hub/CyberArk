package com.keyforge.cyberarkpoc.extract;

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
import java.net.URI;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Safes paging against the local mock (FABRICATED data in the documented shape). */
class OffsetPagerTest {

    private static final ExtractionSettings FAST = new ExtractionSettings(null, 0, 1000);

    private MockCyberArkServer mock;

    @AfterEach
    void stop() {
        if (mock != null) {
            mock.close();
        }
    }

    private PvwaClient client(MockDataset data) throws IOException {
        mock = MockCyberArkServer.start(data, 0);
        return new PvwaClient(new PvwaConfig(URI.create(mock.rootUrl() + MockCyberArkServer.PVWA_APP), "CyberArk",
                MockCyberArkServer.MOCK_VAULT_USERNAME, MockCyberArkServer.MOCK_VAULT_PASSWORD,
                Duration.ofSeconds(5), null));
    }

    @Test
    void readsEveryPageWithTheDocumentedDefaultPageSize() throws IOException {
        try (PvwaClient client = client(SampleData.demo())) {
            FetchResult result = PvwaExtraction.safes(FAST).fetch().apply(client);

            assertEquals(30, result.records().size());
            assertEquals(2, result.pages(), "30 safes with limit 25");
            assertTrue(result.complete(), result.notes().toString());
            assertEquals(30, result.reportedTotal());
            assertEquals("MOCK-Safe-30", result.records().get(29).get("safeUrlId").asText());
        }
        assertEquals(0, mock.openPvwaSessions());
    }

    @Test
    void keepsUnknownFieldsUntouched() throws IOException {
        try (PvwaClient client = client(SampleData.demo())) {
            FetchResult result = PvwaExtraction.safes(FAST).fetch().apply(client);

            assertEquals("kept as-is", result.records().get(29).get("mockTenantSpecificField").asText());
            assertEquals("Administrator", result.records().get(0).get("creator").get("name").asText());
        }
    }

    @Test
    void configuredPageSizeIsUsed() throws IOException {
        try (PvwaClient client = client(SampleData.demo())) {
            FetchResult result = PvwaExtraction.safes(new ExtractionSettings(10, 0, 1000)).fetch().apply(client);

            assertEquals(30, result.records().size());
            // 3 full pages, then one more request: a full page without nextLink may still be followed by more
            // (the docs say nextLink can be absent when a limit is sent), so only an empty or short page ends it.
            assertEquals(4, result.pages());
            assertTrue(result.complete());
        }
    }

    @Test
    void wrongReportedCountMarksTheResultIncomplete() throws IOException {
        try (PvwaClient client = client(SampleData.demo())) {
            mock.fail(MockCyberArkServer.PVWA_SAFES, Fault.WRONG_COUNT);
            FetchResult result = PvwaExtraction.safes(FAST).fetch().apply(client);

            assertFalse(result.complete());
            assertTrue(result.notes().get(0).contains("count 31"), result.notes().toString());
        }
    }

    @Test
    void serverIgnoringOffsetIsDetectedInsteadOfLoopingForever() throws IOException {
        try (PvwaClient client = client(SampleData.demo())) {
            mock.fail(MockCyberArkServer.PVWA_SAFES, Fault.IGNORE_OFFSET);
            FetchResult result = PvwaExtraction.safes(FAST).fetch().apply(client);

            assertFalse(result.complete());
            assertEquals(25, result.records().size());
            assertEquals(2, result.pages());
        }
    }

    @Test
    void pageLimitStopsAndMarksIncomplete() throws IOException {
        try (PvwaClient client = client(SampleData.demo())) {
            FetchResult result = PvwaExtraction.safes(new ExtractionSettings(10, 0, 2)).fetch().apply(client);

            assertFalse(result.complete());
            assertEquals(20, result.records().size());
        }
    }

    @Test
    void recordWithoutItsIdIsCountedNotStored() throws IOException {
        MockDataset data = new MockDataset().safe("S1", "S1", 1).safe("S2", "S2", 2).withoutSafeField("safeUrlId");
        try (PvwaClient client = client(data)) {
            FetchResult result = PvwaExtraction.safes(FAST).fetch().apply(client);

            assertEquals(1, result.records().size());
            assertEquals(1, result.missingId());
            assertTrue(result.complete(), "count 2 = 1 stored + 1 without id");
        }
    }

    @Test
    void permissionErrorIsReportedNotSwallowed() throws IOException {
        try (PvwaClient client = client(SampleData.demo())) {
            mock.fail(MockCyberArkServer.PVWA_SAFES, Fault.HTTP_403);
            CyberArkApiException e = assertThrows(CyberArkApiException.class,
                    () -> PvwaExtraction.safes(FAST).fetch().apply(client));

            assertEquals(CyberArkApiException.Kind.AUTHENTICATION, e.kind());
            assertEquals(403, e.httpStatus());
        }
    }

    @Test
    void malformedPageIsAnInvalidResponse() throws IOException {
        try (PvwaClient client = client(SampleData.demo())) {
            mock.fail(MockCyberArkServer.PVWA_SAFES, Fault.MALFORMED_JSON);
            CyberArkApiException e = assertThrows(CyberArkApiException.class,
                    () -> PvwaExtraction.safes(FAST).fetch().apply(client));

            assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE, e.kind());
        }
    }
}
