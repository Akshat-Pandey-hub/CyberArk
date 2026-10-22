package com.keyforge.cyberarkpoc.check;

import com.keyforge.cyberarkpoc.MockFixture;
import com.keyforge.cyberarkpoc.check.PolicyHealthCheck.PolicyHealthReport;
import com.keyforge.cyberarkpoc.client.CyberArkApiException;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer.Fault;
import com.keyforge.cyberarkpoc.mock.MockDataset;
import com.keyforge.cyberarkpoc.mock.SampleData;
import com.keyforge.cyberarkpoc.model.Policy;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Use case 2 on FABRICATED data served by the mock. */
class PolicyHealthCheckTest {

    private static List<String> ids(List<Policy> policies) {
        return policies.stream().map(Policy::policyId).toList();
    }

    @Test
    void errorAndWarningPoliciesAreFlagged() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            PolicyHealthReport report = new PolicyHealthCheck(f.client).run();

            assertEquals(7, report.totalPolicies());
            assertEquals(List.of("pol-002", "pol-003", "pol-007"), ids(report.flagged()));
            assertTrue(report.unrecognisedStatus().isEmpty());
            assertEquals("MOCK_TARGET_UNREACHABLE", report.flagged().get(0).statusCode());
        }
    }

    @Test
    void statusCasingDoesNotMatter() {
        MockDataset data = new MockDataset()
                .policy("p1", "P1", "ERROR", null, null)
                .policy("p2", "P2", "warning", null, null)
                .policy("p3", "P3", "ACTIVE", null, null);
        try (MockFixture f = MockFixture.start(data)) {
            assertEquals(List.of("p1", "p2"), ids(new PolicyHealthCheck(f.client).run().flagged()));
        }
    }

    @Test
    void healthyPoliciesProduceNoFindings() {
        MockDataset data = new MockDataset()
                .policy("p1", "P1", "Active", null, null)
                .policy("p2", "P2", "Suspended", null, null)
                .policy("p3", "P3", "Expired", null, null)
                .policy("p4", "P4", "Validating", null, null);
        try (MockFixture f = MockFixture.start(data)) {
            PolicyHealthReport report = new PolicyHealthCheck(f.client).run();

            assertEquals(4, report.totalPolicies());
            assertTrue(report.flagged().isEmpty());
            assertTrue(report.unrecognisedStatus().isEmpty());
        }
    }

    @Test
    void emptyPolicyListIsReportedAsSuch() {
        try (MockFixture f = MockFixture.start(new MockDataset())) {
            PolicyHealthReport report = new PolicyHealthCheck(f.client).run();

            assertTrue(report.noPolicies());
            assertTrue(report.flagged().isEmpty());
        }
    }

    @Test
    void unexpectedOrMissingStatusIsReportedSeparately() {
        MockDataset data = new MockDataset()
                .policy("p1", "P1", "Broken", null, null)
                .policy("p2", "P2", null, null, null)
                .policy("p3", "P3", "Error", null, null);
        try (MockFixture f = MockFixture.start(data)) {
            PolicyHealthReport report = new PolicyHealthCheck(f.client).run();

            assertEquals(List.of("p3"), ids(report.flagged()));
            assertEquals(List.of("p1", "p2"), ids(report.unrecognisedStatus()));
        }
    }

    @Test
    void flaggedPolicyOnALaterPageIsFound() {
        MockDataset data = new MockDataset().policyPageSize(1)
                .policy("p1", "P1", "Active", null, null)
                .policy("p2", "P2", "Active", null, null)
                .policy("p3", "P3", "Warning", null, null);
        try (MockFixture f = MockFixture.start(data)) {
            assertEquals(List.of("p3"), ids(new PolicyHealthCheck(f.client).run().flagged()));
            assertEquals(3, f.mock.requestCount(MockCyberArkServer.POLICIES));
        }
    }

    @Test
    void failedRequestFailsTheCheck() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.POLICIES, Fault.HTTP_500);
            assertThrows(CyberArkApiException.class, () -> new PolicyHealthCheck(f.client).run());

            f.mock.fail(MockCyberArkServer.POLICIES, Fault.MALFORMED_JSON);
            CyberArkApiException e = assertThrows(CyberArkApiException.class, () -> new PolicyHealthCheck(f.client).run());
            assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE, e.kind());
        }
    }

    @Test
    void failedLoginFailsTheCheck() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.TOKEN, Fault.HTTP_500);
            CyberArkApiException e = assertThrows(CyberArkApiException.class, () -> new PolicyHealthCheck(f.client).run());
            assertEquals(CyberArkApiException.Kind.HTTP_STATUS, e.kind());
            assertEquals(0, f.mock.requestCount(MockCyberArkServer.POLICIES), "no API call without a token");
        }
        try (MockFixture f = MockFixture.startWithSecret(SampleData.demo(), "wrong-secret")) {
            CyberArkApiException e = assertThrows(CyberArkApiException.class, () -> new PolicyHealthCheck(f.client).run());
            assertEquals(CyberArkApiException.Kind.AUTHENTICATION, e.kind());
        }
    }
}
