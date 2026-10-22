package com.keyforge.cyberarkpoc.check;

import com.keyforge.cyberarkpoc.MockFixture;
import com.keyforge.cyberarkpoc.check.ApproverGroupCheck.ApproverGroupReport;
import com.keyforge.cyberarkpoc.check.ApproverGroupCheck.Outcome;
import com.keyforge.cyberarkpoc.check.ApproverGroupCheck.Reason;
import com.keyforge.cyberarkpoc.check.ApproverGroupCheck.RoleResult;
import com.keyforge.cyberarkpoc.client.CyberArkApiException;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer.Fault;
import com.keyforge.cyberarkpoc.mock.MockDataset;
import com.keyforge.cyberarkpoc.mock.SampleData;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.keyforge.cyberarkpoc.mock.MockDataset.activeUser;
import static com.keyforge.cyberarkpoc.mock.MockDataset.userWithStatus;
import static com.keyforge.cyberarkpoc.mock.MockDataset.userWithStatuses;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Use case 1 on FABRICATED data served by the mock. */
class ApproverGroupCheckTest {

    private static final String PATTERN = ApproverGroupCheck.DEFAULT_PATTERN;

    private static RoleResult role(ApproverGroupReport report, String roleName) {
        return report.roles().stream().filter(r -> r.role().name().equals(roleName)).findFirst().orElseThrow();
    }

    private static List<Reason> reasons(RoleResult result) {
        return result.excluded().stream().map(ApproverGroupCheck.ExcludedMember::reason).toList();
    }

    @Test
    void demoDatasetGivesTheExpectedOutcomes() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            ApproverGroupReport report = new ApproverGroupCheck(f.client).run();

            assertEquals(5, report.roles().size(), "the Azure role must not match the AWS pattern");

            RoleResult finance = role(report, "APP-CYA-ISPSS-SCA-AWS-Finance-BUApprovers");
            assertEquals(Outcome.SUFFICIENT, finance.outcome());
            assertEquals(3, finance.validApprovers().size());
            assertEquals("MOCK Finance AWS approvers", finance.details().description());

            RoleResult hr = role(report, "APP-CYA-ISPSS-SCA-AWS-HR-BUApprovers");
            assertEquals(Outcome.INSUFFICIENT, hr.outcome());
            assertEquals(2, hr.validApprovers().size());
            assertEquals(List.of(Reason.STATUS_UNKNOWN), reasons(hr));

            RoleResult payments = role(report, "APP-CYA-ISPSS-SCA-AWS-Payments-BUApprovers");
            assertEquals(Outcome.INSUFFICIENT, payments.outcome());
            assertEquals(List.of(Reason.ACCOUNT_NOT_ACTIVE), reasons(payments));

            RoleResult marketing = role(report, "APP-CYA-ISPSS-SCA-AWS-Marketing-BUApprovers");
            assertEquals(Outcome.INSUFFICIENT, marketing.outcome());
            assertEquals(2, marketing.validApprovers().size());
            assertEquals("MOCK-Marketing-Leads", marketing.unresolvedGroups().get(0).name());

            RoleResult operations = role(report, "APP-CYA-ISPSS-SCA-AWS-Operations-BUApprovers");
            assertEquals(Outcome.SUFFICIENT, operations.outcome(), "the nested role adds the third approver");
            assertEquals(3, operations.validApprovers().size());
            assertEquals(List.of(Reason.USER_NOT_FOUND), reasons(operations));
            assertEquals("APP-CYA-MOCK-Operations-Leads", operations.excluded().get(0).viaRole());

            assertEquals(3, report.insufficient().size());
        }
    }

    @Test
    void roleWithNoMembersIsInsufficient() {
        MockDataset data = new MockDataset().role("r1", "APP-CYA-ISPSS-SCA-AWS-Empty-BUApprovers", "empty");
        try (MockFixture f = MockFixture.start(data)) {
            RoleResult result = new ApproverGroupCheck(f.client).run().roles().get(0);

            assertEquals(Outcome.INSUFFICIENT, result.outcome());
            assertTrue(result.validApprovers().isEmpty());
        }
    }

    @Test
    void noMatchingRolesIsReportedAsSuch() {
        MockDataset data = new MockDataset().role("r1", "SOME-OTHER-ROLE", "not an approver role");
        try (MockFixture f = MockFixture.start(data)) {
            ApproverGroupReport report = new ApproverGroupCheck(f.client).run();

            assertTrue(report.noRolesFound());
            assertTrue(report.insufficient().isEmpty());
        }
    }

    @Test
    void userReachedTwiceCountsOnce() {
        MockDataset data = new MockDataset()
                .role("top", "APP-CYA-ISPSS-SCA-AWS-Dup-BUApprovers", "dup")
                .userMember("top", activeUser("a"))
                .userMember("top", activeUser("b"))
                .member("top", "nested", "Nested", "Role")
                .role("nested", "Nested", "nested")
                .member("nested", "a", "a@example.test", "User");
        try (MockFixture f = MockFixture.start(data)) {
            RoleResult result = new ApproverGroupCheck(f.client).run().roles().get(0);

            assertEquals(2, result.validApprovers().size());
            assertEquals(Outcome.INSUFFICIENT, result.outcome());
        }
    }

    @Test
    void nestedRoleCycleTerminates() {
        MockDataset data = new MockDataset()
                .role("a", "APP-CYA-ISPSS-SCA-AWS-Loop-BUApprovers", "loop")
                .userMember("a", activeUser("u1"))
                .member("a", "b", "B", "Role")
                .role("b", "B", "b")
                .userMember("b", activeUser("u2"))
                .member("b", "a", "A", "Role");
        try (MockFixture f = MockFixture.start(data)) {
            RoleResult result = new ApproverGroupCheck(f.client).run().roles().get(0);

            assertEquals(2, result.validApprovers().size());
        }
    }

    @Test
    void thresholdIsConfigurable() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            ApproverGroupReport report = new ApproverGroupCheck(f.client, PATTERN, 2).run();

            assertEquals(Outcome.SUFFICIENT, role(report, "APP-CYA-ISPSS-SCA-AWS-HR-BUApprovers").outcome());
            assertEquals(0, report.insufficient().size());
        }
        assertThrows(IllegalArgumentException.class, () -> new ApproverGroupCheck(null, PATTERN, 0));
    }

    @Test
    void eligibilityUsesStatusEnumNotTheLocalizedStatus() {
        MockDataset data = new MockDataset()
                .role("r1", "APP-CYA-ISPSS-SCA-AWS-Status-BUApprovers", "status")
                // Pair from the official "Use queries" example: Status "Not Invited", StatusEnum "Created".
                .userMember("r1", userWithStatuses("created", "Created", "Not Invited"))
                // Localized display text with the enum Active: eligible.
                .userMember("r1", userWithStatuses("localized", "Active", "Aktiv"))
                // Enum compared case-insensitively.
                .userMember("r1", userWithStatuses("lower", "active", "Active"))
                // No StatusEnum: not eligible even though the display text says Active (no fallback).
                .userMember("r1", userWithStatuses("noenum", null, "Active"));
        try (MockFixture f = MockFixture.start(data)) {
            RoleResult result = new ApproverGroupCheck(f.client).run().roles().get(0);

            assertEquals(List.of("localized", "lower"),
                    result.validApprovers().stream().map(u -> u.id()).toList());
            assertEquals(List.of(Reason.ACCOUNT_NOT_ACTIVE, Reason.STATUS_UNKNOWN), reasons(result));
            assertTrue(result.excluded().get(0).detail().contains("StatusEnum=Created"));
            assertTrue(result.excluded().get(0).detail().contains("Status=Not Invited"), "kept for display");
            assertEquals(Outcome.INSUFFICIENT, result.outcome());
        }
    }

    @Test
    void invitedAndSuspendedAreNotEligibleUnderTheCurrentActiveOnlyRule() {
        // Rule-dependent: whether Invited should count is an open business decision.
        MockDataset data = new MockDataset()
                .role("r1", "APP-CYA-ISPSS-SCA-AWS-Pending-BUApprovers", "pending")
                .userMember("r1", userWithStatus("invited", "Invited"))
                .userMember("r1", userWithStatus("suspended", "Suspended"));
        try (MockFixture f = MockFixture.start(data)) {
            RoleResult result = new ApproverGroupCheck(f.client).run().roles().get(0);

            assertTrue(result.validApprovers().isEmpty());
            assertEquals(List.of(Reason.ACCOUNT_NOT_ACTIVE, Reason.ACCOUNT_NOT_ACTIVE), reasons(result));
        }
    }

    @Test
    void memberTypeCasingDoesNotMatterAndUnknownTypesAreExcluded() {
        MockDataset data = new MockDataset()
                .role("r1", "APP-CYA-ISPSS-SCA-AWS-Types-BUApprovers", "types")
                .user(activeUser("u1"))
                .member("r1", "u1", "u1@example.test", "USER")
                .user(activeUser("u2"))
                .member("r1", "u2", "u2@example.test", "user")
                .member("r1", "x1", "Something", "Device");
        try (MockFixture f = MockFixture.start(data)) {
            RoleResult result = new ApproverGroupCheck(f.client).run().roles().get(0);

            assertEquals(2, result.validApprovers().size());
            assertEquals(List.of(Reason.UNKNOWN_MEMBER_TYPE), reasons(result));
        }
    }

    @Test
    void failedMemberRequestFailsTheWholeCheck() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.GET_ROLE_MEMBERS, Fault.HTTP_500);
            CyberArkApiException e = assertThrows(CyberArkApiException.class, () -> new ApproverGroupCheck(f.client).run());
            assertEquals(CyberArkApiException.Kind.HTTP_STATUS, e.kind());
        }
    }

    @Test
    void failedRoleSearchFailsTheWholeCheck() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.REDROCK_ROLE, Fault.SUCCESS_FALSE);
            assertThrows(CyberArkApiException.class, () -> new ApproverGroupCheck(f.client).run());
        }
    }

    @Test
    void failedUserLookupFailsTheWholeCheck() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.REDROCK_USER, Fault.MALFORMED_JSON);
            CyberArkApiException e = assertThrows(CyberArkApiException.class, () -> new ApproverGroupCheck(f.client).run());
            assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE, e.kind());
        }
    }
}
