package com.keyforge.cyberarkpoc.check;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyforge.cyberarkpoc.check.PolicyHealthCheck.Outcome;
import com.keyforge.cyberarkpoc.check.PolicyHealthCheck.PolicyResult;
import com.keyforge.cyberarkpoc.config.PolicyConfig.Api;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The per-policy outcome rules on hand-written FABRICATED policies (no HTTP). */
class PolicyHealthCheckTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode json(String text) {
        try {
            return MAPPER.readTree(text);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    /** A UAP policy with {@code statusJson} as the value of {@code metadata.status.status}. */
    private static PolicyResult uap(String statusJson) {
        return PolicyHealthCheck.evaluate(Api.UAP, json("""
                {"metadata": {"policyId": "p1", "name": "P1",
                  "status": {"status": %s, "statusCode": "C1", "statusDescription": "D1"},
                  "policyEntitlement": {"targetCategory": "Cloud Console", "locationType": "AWS"}}}"""
                .formatted(statusJson)));
    }

    private static PolicyResult sca(String statusJson) {
        return PolicyHealthCheck.evaluate(Api.SCA, json("""
                {"policyId": "aws_1", "name": "S1", "status": %s, "cloudProvider": 0,
                 "faultCode": 1001, "statusTooltipMessage": "role missing"}""".formatted(statusJson)));
    }

    @Test
    void uapErrorAndWarningAreFindingsWithTheirCodeAndDescription() {
        for (String status : new String[] {"Error", "Warning"}) {
            PolicyResult r = uap("\"" + status + "\"");
            assertEquals(Outcome.FINDING, r.outcome(), status);
            assertEquals(status, r.status());
            assertEquals("C1", r.statusCode());
            assertEquals("D1", r.statusDescription());
            assertEquals("status " + status + ": C1 - D1", r.reason());
            assertEquals("p1", r.policyId());
            assertEquals("Cloud Console", r.targetCategory());
            assertEquals("AWS", r.locationType());
        }
    }

    @Test
    void uapOtherDocumentedStatusesAreNoFinding() {
        for (String status : new String[] {"Active", "Suspended", "Expired", "Validating"}) {
            assertEquals(Outcome.NO_FINDING, uap("\"" + status + "\"").outcome(), status);
        }
    }

    @Test
    void uapStatusIsComparedIgnoringCaseAndShownAsDocumented() {
        PolicyResult r = uap("\"error\"");
        assertEquals(Outcome.FINDING, r.outcome());
        assertEquals("Error", r.status());
    }

    @Test
    void uapMissingOrUndocumentedStatusCannotBeVerified() {
        assertEquals(Outcome.CANNOT_VERIFY, uap("null").outcome());
        assertEquals(Outcome.CANNOT_VERIFY, uap("\"\"").outcome());
        PolicyResult undocumented = uap("\"Disabled\"");
        assertEquals(Outcome.CANNOT_VERIFY, undocumented.outcome());
        assertEquals("undocumented status 'Disabled'", undocumented.reason());
        assertEquals(Outcome.CANNOT_VERIFY, uap("4").outcome(), "a number is not a documented UAP status");

        PolicyResult noStatusObject = PolicyHealthCheck.evaluate(Api.UAP,
                json("{\"metadata\": {\"policyId\": \"p2\", \"name\": \"P2\"}}"));
        assertEquals(Outcome.CANNOT_VERIFY, noStatusObject.outcome());
        assertEquals("p2", noStatusObject.policyId());

        PolicyResult noMetadata = PolicyHealthCheck.evaluate(Api.UAP, json("{}"));
        assertEquals(Outcome.CANNOT_VERIFY, noMetadata.outcome());
        assertNull(noMetadata.policyId());
    }

    @Test
    void aFindingWithoutDetailSaysSo() {
        PolicyResult r = PolicyHealthCheck.evaluate(Api.UAP,
                json("{\"metadata\": {\"policyId\": \"p1\", \"status\": {\"status\": \"Warning\"}}}"));
        assertEquals(Outcome.FINDING, r.outcome());
        assertTrue(r.reason().contains("no status code or description"), r.reason());
    }

    @Test
    void scaErrorAndWarningNumbersAreFindingsWithFaultCodeAndTooltip() {
        PolicyResult error = sca("4");
        assertEquals(Outcome.FINDING, error.outcome());
        assertEquals("Error (4)", error.status());
        assertEquals("1001", error.statusCode());
        assertEquals("role missing", error.statusDescription());
        assertEquals("AWS", error.locationType());
        assertEquals("aws_1", error.policyId());
        assertEquals(Outcome.FINDING, sca("5").outcome());
        assertEquals("Warning (5)", sca("5").status());
    }

    @Test
    void scaOtherDocumentedNumbersAreNoFinding() {
        for (String status : new String[] {"1", "3", "6"}) {
            assertEquals(Outcome.NO_FINDING, sca(status).outcome(), status);
        }
    }

    @Test
    void scaMissingOrUndocumentedStatusCannotBeVerified() {
        assertEquals(Outcome.CANNOT_VERIFY, sca("null").outcome());
        assertEquals(Outcome.CANNOT_VERIFY, sca("2").outcome(), "2 is not documented");
        assertEquals(Outcome.CANNOT_VERIFY, sca("99").outcome());
        assertEquals(Outcome.CANNOT_VERIFY, sca("\"4\"").outcome(), "the documented type is integer");
        assertEquals(Outcome.CANNOT_VERIFY, PolicyHealthCheck.evaluate(Api.SCA, json("{\"policyId\": \"x\"}")).outcome());
    }
}
