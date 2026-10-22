package com.keyforge.cyberarkpoc.check;

import com.keyforge.cyberarkpoc.MockFixture;
import com.keyforge.cyberarkpoc.check.ApproverGroupCheck.ApproverGroupReport;
import com.keyforge.cyberarkpoc.check.ApproverGroupCheck.MemberOutcome;
import com.keyforge.cyberarkpoc.check.ApproverGroupCheck.MemberResult;
import com.keyforge.cyberarkpoc.check.ApproverGroupCheck.Outcome;
import com.keyforge.cyberarkpoc.check.ApproverGroupCheck.RoleResult;
import com.keyforge.cyberarkpoc.client.CyberArkApiException;
import com.keyforge.cyberarkpoc.client.CyberArkClient;
import com.keyforge.cyberarkpoc.config.CyberArkConfig.RoleMembersApi;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer.Fault;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer.MemberShape;
import com.keyforge.cyberarkpoc.mock.MockDataset;
import com.keyforge.cyberarkpoc.mock.SampleData;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static com.keyforge.cyberarkpoc.mock.MockDataset.activeUser;
import static com.keyforge.cyberarkpoc.mock.MockDataset.userWithStatus;
import static com.keyforge.cyberarkpoc.mock.MockDataset.userWithStatuses;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Use case 1 on FABRICATED data served by the mock (documented shapes; not a tenant). */
class ApproverGroupCheckTest {

    private static final String PATTERN = ApproverGroupCheck.DEFAULT_PATTERN;
    private static final String NAME = "APP-CYA-ISPSS-SCA-AWS-Test-BUApprovers";

    private static RoleResult role(ApproverGroupReport report, String roleName) {
        return report.roles().stream().filter(r -> r.role().name().equals(roleName)).findFirst().orElseThrow();
    }

    private static RoleResult only(MockDataset data) {
        try (MockFixture f = MockFixture.start(data)) {
            return new ApproverGroupCheck(f.client).run().roles().get(0);
        }
    }

    private static List<MemberOutcome> outcomes(RoleResult result) {
        return result.members().stream().map(MemberResult::outcome).toList();
    }

    @Test
    void demoDatasetGivesEachOutcomeWithReasons() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            ApproverGroupReport report = new ApproverGroupCheck(f.client).run();

            assertEquals(5, report.roles().size(), "the Azure role and the nested role must not match the pattern");
            assertTrue(report.search().complete(), report.search().notes().toString());

            RoleResult finance = role(report, "APP-CYA-ISPSS-SCA-AWS-Finance-BUApprovers");
            assertEquals(Outcome.PASS, finance.outcome());
            assertEquals(3, finance.directMembers());
            assertEquals(3, finance.activeUsers());
            assertEquals(Boolean.TRUE, finance.totalThresholdMet());
            assertEquals(Boolean.TRUE, finance.activeThresholdMet());
            assertEquals("MOCK Finance AWS approvers", finance.details().description());

            RoleResult hr = role(report, "APP-CYA-ISPSS-SCA-AWS-HR-BUApprovers");
            assertEquals(Outcome.CANNOT_VERIFY, hr.outcome(), "the user without StatusEnum could be the third");
            assertEquals(2, hr.activeUsers());
            assertNull(hr.activeThresholdMet());
            assertTrue(outcomes(hr).contains(MemberOutcome.USER_STATUS_MISSING));

            RoleResult payments = role(report, "APP-CYA-ISPSS-SCA-AWS-Payments-BUApprovers");
            assertEquals(Outcome.FAIL, payments.outcome());
            assertEquals(Boolean.TRUE, payments.totalThresholdMet());
            assertEquals(Boolean.FALSE, payments.activeThresholdMet());
            assertTrue(payments.reasons().get(1).startsWith("only 2 verified active user(s)"), payments.reasons().toString());

            RoleResult marketing = role(report, "APP-CYA-ISPSS-SCA-AWS-Marketing-BUApprovers");
            assertEquals(Outcome.CANNOT_VERIFY, marketing.outcome(), "the group cannot be expanded");
            assertEquals(Map.of("User", 2, "Group", 1, "Role", 0, "Unknown", 0), marketing.directMembersByType());
            assertEquals(3, marketing.directMembers(), "a group is a direct member");
            assertEquals(2, marketing.activeUsers(), "but never an approver");

            RoleResult operations = role(report, "APP-CYA-ISPSS-SCA-AWS-Operations-BUApprovers");
            assertEquals(Outcome.PASS, operations.outcome(), "the expanded nested role adds the third active user");
            assertEquals(3, operations.activeUsers());
            assertEquals(Map.of("User", 2, "Group", 0, "Role", 1, "Unknown", 0), operations.directMembersByType());
            MemberResult deleted = operations.members().stream()
                    .filter(m -> m.outcome() == MemberOutcome.USER_NOT_FOUND).findFirst().orElseThrow();
            assertEquals("APP-CYA-MOCK-Operations-Leads", deleted.viaRoleName());

            assertEquals(2, report.count(Outcome.PASS));
            assertEquals(1, report.count(Outcome.FAIL));
            assertEquals(2, report.count(Outcome.CANNOT_VERIFY));
        }
    }

    @Test
    void fewerThanThreeDirectMembersFails() {
        RoleResult r = only(new MockDataset().role("r1", NAME, "two")
                .userMember("r1", activeUser("a")).userMember("r1", activeUser("b")));

        assertEquals(Outcome.FAIL, r.outcome());
        assertEquals(Boolean.FALSE, r.totalThresholdMet());
        assertEquals(Boolean.FALSE, r.activeThresholdMet());
        assertTrue(r.reasons().get(0).startsWith("only 2 direct member(s)"));
    }

    @Test
    void threeMembersButFewerThanThreeActiveUsersFails() {
        RoleResult r = only(new MockDataset().role("r1", NAME, "inactive")
                .userMember("r1", activeUser("a"))
                .userMember("r1", userWithStatus("b", "Suspended"))
                .userMember("r1", userWithStatus("c", "Invited")));

        assertEquals(Outcome.FAIL, r.outcome());
        assertEquals(3, r.directMembers());
        assertEquals(1, r.activeUsers());
        assertEquals(List.of(MemberOutcome.ACTIVE_USER, MemberOutcome.USER_NOT_ACTIVE, MemberOutcome.USER_NOT_ACTIVE),
                outcomes(r));
    }

    @Test
    void noMatchingRolesIsReportedWithTheVisibilityLimitation() {
        try (MockFixture f = MockFixture.start(new MockDataset().role("r1", "SOME-OTHER-ROLE", "other"))) {
            ApproverGroupReport report = new ApproverGroupCheck(f.client).run();

            assertTrue(report.noRolesFound());
            assertTrue(report.search().complete());
            assertTrue(ApproverGroupCheck.VISIBILITY_NOTE.contains("not proof"));
        }
    }

    @Test
    void aGroupMakesTheResultUnverifiableUnlessTheThresholdsAreMetAnyway() {
        RoleResult open = only(new MockDataset().role("r1", NAME, "g")
                .userMember("r1", activeUser("a")).userMember("r1", activeUser("b"))
                .member("r1", "g1", "Some AD group", "Group"));
        RoleResult met = only(new MockDataset().role("r1", NAME, "g")
                .userMember("r1", activeUser("a")).userMember("r1", activeUser("b")).userMember("r1", activeUser("c"))
                .member("r1", "g1", "Some AD group", "Group"));

        assertEquals(Outcome.CANNOT_VERIFY, open.outcome());
        assertTrue(outcomes(open).contains(MemberOutcome.GROUP_NOT_EXPANDED));
        assertEquals(Outcome.PASS, met.outcome());
        assertEquals(4, met.directMembers());
    }

    @Test
    void aNestedRoleThatIsNotAnExplicitListOrNotVisibleIsNotExpanded() {
        RoleResult script = only(new MockDataset().role("r1", NAME, "n")
                .userMember("r1", activeUser("a")).userMember("r1", activeUser("b"))
                .member("r1", "child", "Child", "Role")
                .roleOfType("child", "Child", "script role", "Script")
                .userMember("child", activeUser("c")));
        RoleResult hidden = only(new MockDataset().role("r1", NAME, "n")
                .userMember("r1", activeUser("a")).userMember("r1", activeUser("b"))
                .member("r1", "child", "Child", "Role")
                .role("child", "Child", "hidden").hiddenRole("child")
                .userMember("child", activeUser("c")));

        assertEquals(Outcome.CANNOT_VERIFY, script.outcome());
        assertEquals(2, script.activeUsers(), "the Script role's members are not counted");
        assertTrue(outcomes(script).contains(MemberOutcome.NESTED_ROLE_NOT_EXPANDED));
        assertEquals(Outcome.CANNOT_VERIFY, hidden.outcome());
        assertTrue(outcomes(hidden).contains(MemberOutcome.NESTED_ROLE_NOT_VISIBLE));
    }

    @Test
    void aTopLevelRoleThatIsNotAPrincipalListCannotFailOnItsMemberCount() {
        RoleResult r = only(new MockDataset().roleOfType("r1", NAME, "everybody", "Everybody")
                .userMember("r1", activeUser("a")));

        assertEquals(Outcome.CANNOT_VERIFY, r.outcome());
        assertNull(r.totalThresholdMet());
        assertTrue(r.notes().get(0).contains("'Everybody'"));
    }

    @Test
    void missingUserRowsAreUnresolvedNotInactive() {
        RoleResult couldPass = only(new MockDataset().role("r1", NAME, "m")
                .userMember("r1", activeUser("a")).userMember("r1", activeUser("b"))
                .member("r1", "gone", "gone@example.test", "User"));
        RoleResult cannotPass = only(new MockDataset().role("r1", NAME, "m")
                .userMember("r1", activeUser("a"))
                .userMember("r1", userWithStatus("b", "Suspended"))
                .member("r1", "gone", "gone@example.test", "User"));

        assertEquals(Outcome.CANNOT_VERIFY, couldPass.outcome());
        assertTrue(outcomes(couldPass).contains(MemberOutcome.USER_NOT_FOUND));
        assertEquals(Outcome.FAIL, cannotPass.outcome(), "even if the missing user were active, only 2");
        assertTrue(cannotPass.reasons().get(1).contains("even if the 1 unresolved user(s) were active"));
    }

    @Test
    void duplicateMembersAndUsersReachedTwiceCountOnce() {
        RoleResult r = only(new MockDataset().role("r1", NAME, "dup")
                .userMember("r1", activeUser("a"))
                .member("r1", "a", "a@example.test", "User")
                .userMember("r1", activeUser("b"))
                .member("r1", "child", "Child", "Role")
                .role("child", "Child", "nested")
                .member("child", "a", "a@example.test", "User"));

        assertEquals(3, r.directMembers(), "a, b and the child role; the repeated a is not counted");
        assertEquals(2, r.activeUsers());
        assertTrue(outcomes(r).contains(MemberOutcome.DUPLICATE));
        assertTrue(outcomes(r).contains(MemberOutcome.USER_ALREADY_COUNTED));
        assertEquals(Outcome.FAIL, r.outcome());
    }

    @Test
    void nestedRoleCycleTerminates() {
        RoleResult r = only(new MockDataset()
                .role("a", NAME, "loop").userMember("a", activeUser("u1")).member("a", "b", "B", "Role")
                .role("b", "B", "b").userMember("b", activeUser("u2")).member("b", "a", "A", "Role"));

        assertEquals(2, r.activeUsers());
        assertTrue(outcomes(r).contains(MemberOutcome.ROLE_ALREADY_EXPANDED));
    }

    @Test
    void eligibilityUsesStatusEnumNotTheLocalizedStatus() {
        RoleResult r = only(new MockDataset().role("r1", NAME, "status")
                // Pair from the official "Use queries" example: Status "Not Invited", StatusEnum "Created".
                .userMember("r1", userWithStatuses("created", "Created", "Not Invited"))
                .userMember("r1", userWithStatuses("localized", "Active", "Aktiv"))
                .userMember("r1", userWithStatuses("lower", "active", "Active"))
                .userMember("r1", userWithStatuses("noenum", null, "Active")));

        assertEquals(List.of("localized", "lower"), r.members().stream().filter(MemberResult::countsAsActive)
                .map(MemberResult::id).toList());
        assertEquals(List.of(MemberOutcome.USER_NOT_ACTIVE, MemberOutcome.ACTIVE_USER, MemberOutcome.ACTIVE_USER,
                MemberOutcome.USER_STATUS_MISSING), outcomes(r));
        assertTrue(r.members().get(0).detail().contains("Status=Not Invited"), "kept for display");
        assertEquals(Outcome.CANNOT_VERIFY, r.outcome(), "the user without StatusEnum could be the third");
    }

    @Test
    void unknownMemberTypesAreReportedAndTypeCasingDoesNotMatter() {
        RoleResult r = only(new MockDataset().role("r1", NAME, "types")
                .user(activeUser("u1")).member("r1", "u1", "u1@example.test", "USER")
                .user(activeUser("u2")).member("r1", "u2", "u2@example.test", "user")
                .member("r1", "x1", "Something", "Device"));

        assertEquals(2, r.activeUsers());
        assertEquals(1, r.directMembersByType().get("Unknown"));
        assertEquals(Outcome.CANNOT_VERIFY, r.outcome(), "the unknown member might be a third user");
    }

    @Test
    void anIncompleteMemberListCannotFail() {
        try (MockFixture f = MockFixture.start(new MockDataset().role("r1", NAME, "short")
                .userMember("r1", activeUser("a")).userMember("r1", activeUser("b")))) {
            f.mock.fail(MockCyberArkServer.GET_ROLE_MEMBERS, Fault.WRONG_COUNT);
            RoleResult r = new ApproverGroupCheck(f.client).run().roles().get(0);

            assertEquals(Outcome.CANNOT_VERIFY, r.outcome());
            assertTrue(r.notes().get(0).contains("FullCount 3 but 2 listed"), r.notes().toString());
        }
    }

    @Test
    void theNestedMembersShapeGivesTheSameResults() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.memberShape(MemberShape.NESTED);
            ApproverGroupReport report = new ApproverGroupCheck(f.client).run();

            assertEquals(Outcome.PASS, role(report, "APP-CYA-ISPSS-SCA-AWS-Finance-BUApprovers").outcome());
            assertEquals(Outcome.FAIL, role(report, "APP-CYA-ISPSS-SCA-AWS-Payments-BUApprovers").outcome());
            assertEquals(Outcome.PASS, role(report, "APP-CYA-ISPSS-SCA-AWS-Operations-BUApprovers").outcome());
        }
    }

    @Test
    void theSaasManageMembersPathCanBeSelected() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            CyberArkClient saas = new CyberArkClient(MockFixture.config(f.mock.rootUrl(),
                    MockCyberArkServer.MOCK_CLIENT_SECRET), RoleMembersApi.SAASMANAGE);
            ApproverGroupReport report = new ApproverGroupCheck(saas).run();

            assertEquals(Outcome.PASS, role(report, "APP-CYA-ISPSS-SCA-AWS-Finance-BUApprovers").outcome());
            assertEquals(RoleMembersApi.SAASMANAGE, saas.membersApi());
        }
    }

    @Test
    void anApiErrorOrMalformedMemberResponseIsCheckFailedPerRole() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.GET_ROLE_MEMBERS, Fault.HTTP_500);
            ApproverGroupReport report = new ApproverGroupCheck(f.client).run();

            assertEquals(5, report.count(Outcome.CHECK_FAILED), "the run itself still completes");
            assertTrue(report.roles().get(0).error().contains("HTTP 500"));
            assertNull(report.roles().get(0).totalThresholdMet());
        }
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.GET_ROLE_MEMBERS, Fault.MALFORMED_JSON);
            RoleResult r = new ApproverGroupCheck(f.client).run().roles().get(0);
            assertEquals(Outcome.CHECK_FAILED, r.outcome());
            assertTrue(r.error().contains("INVALID_RESPONSE"));
        }
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.REDROCK_USER, Fault.SUCCESS_FALSE);
            assertEquals(5, new ApproverGroupCheck(f.client).run().count(Outcome.CHECK_FAILED));
        }
    }

    @Test
    void aFailedRoleSearchOrLoginFailsTheWholeCheck() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.REDROCK_ROLE, Fault.SUCCESS_FALSE);
            assertEquals(CyberArkApiException.Kind.API_FAILURE,
                    assertThrows(CyberArkApiException.class, () -> new ApproverGroupCheck(f.client).run()).kind());
        }
        try (MockFixture f = MockFixture.startWithSecret(SampleData.demo(), "wrong-secret")) {
            CyberArkApiException e = assertThrows(CyberArkApiException.class, () -> new ApproverGroupCheck(f.client).run());
            assertEquals(CyberArkApiException.Kind.AUTHENTICATION, e.kind());
            assertFalse(f.client.sanitize(e.getMessage()).contains("wrong-secret"));
        }
    }

    @Test
    void rolesArePagedAndAnInconsistentFullCountMarksTheSearchIncomplete() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            ApproverGroupReport paged = new ApproverGroupCheck(f.client, PATTERN, 3, 2, 100).run();
            assertEquals(5, paged.roles().size());
            assertEquals(3, paged.search().pages(), "5 roles in pages of 2");
            assertTrue(paged.search().complete());
            assertTrue(f.mock.redrockBodies().get(0).contains("\"args\":{\"PageNumber\":1,\"PageSize\":2,\"Limit\":2,"
                    + "\"Caching\":-1}"), f.mock.redrockBodies().get(0));

            f.mock.fail(MockCyberArkServer.REDROCK_ROLE, Fault.WRONG_COUNT);
            ApproverGroupReport wrong = new ApproverGroupCheck(f.client, PATTERN, 3, 2, 100).run();
            assertFalse(wrong.search().complete());
            assertTrue(wrong.search().notes().toString().contains("FullCount 6 but 5"));

            f.mock.fail(MockCyberArkServer.REDROCK_ROLE, Fault.IGNORE_OFFSET);
            ApproverGroupReport stuck = new ApproverGroupCheck(f.client, PATTERN, 3, 2, 100).run();
            assertFalse(stuck.search().complete());
            assertEquals(2, stuck.roles().size(), "the repeated first page is not counted twice");
        }
    }

    @Test
    void thresholdIsConfigurable() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            ApproverGroupReport report = new ApproverGroupCheck(f.client, PATTERN, 2).run();
            assertEquals(Outcome.PASS, role(report, "APP-CYA-ISPSS-SCA-AWS-Payments-BUApprovers").outcome());
        }
        assertThrows(IllegalArgumentException.class, () -> new ApproverGroupCheck(null, PATTERN, 0));
    }
}
