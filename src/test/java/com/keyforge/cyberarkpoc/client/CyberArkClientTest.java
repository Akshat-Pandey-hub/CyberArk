package com.keyforge.cyberarkpoc.client;

import com.keyforge.cyberarkpoc.MockFixture;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer;
import com.keyforge.cyberarkpoc.mock.MockCyberArkServer.Fault;
import com.keyforge.cyberarkpoc.mock.MockDataset;
import com.keyforge.cyberarkpoc.mock.SampleData;
import com.keyforge.cyberarkpoc.model.Role;
import com.keyforge.cyberarkpoc.model.RoleMember;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The client against the local mock (FABRICATED data). */
class CyberArkClientTest {

    private static final String PATTERN = "APP-CYA-ISPSS-SCA-AWS-%-BUApprovers";

    private static CyberArkApiException.Kind failureKind(Runnable call) {
        return assertThrows(CyberArkApiException.class, call::run).kind();
    }

    @Test
    void roleSearchUsesTheLikePattern() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            List<String> names = f.client.findRolesByNamePattern(PATTERN, 1000, 10).roles().stream().map(Role::name).toList();

            assertEquals(5, names.size());
            assertTrue(names.contains("APP-CYA-ISPSS-SCA-AWS-Finance-BUApprovers"));
            assertFalse(names.contains("APP-CYA-ISPSS-SCA-AZURE-Finance-BUApprovers"));
            assertFalse(names.contains("APP-CYA-MOCK-Operations-Leads"));
        }
    }

    @Test
    void quotesInTheSearchValueAreEscaped() {
        MockDataset data = new MockDataset().role("r1", "O'Brien-Approvers", "quote");
        try (MockFixture f = MockFixture.start(data)) {
            assertEquals(1, f.client.findRolesByNamePattern("O'Brien-%", 1000, 10).roles().size());
        }
    }

    @Test
    void roleDetailsAndMembersAreRead() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            assertEquals("APP-CYA-ISPSS-SCA-AWS-Marketing-BUApprovers", f.client.getRole("role-mkt").name());
            assertEquals(3, f.client.getRole("role-mkt").principals().size());

            List<RoleMember> members = f.client.getRoleMembers("role-mkt").members();
            assertEquals(3, members.size());
            assertEquals(RoleMember.Type.GROUP, members.get(2).type());
        }
    }

    @Test
    void unknownRoleIsAnApiFailure() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            assertEquals(CyberArkApiException.Kind.API_FAILURE, failureKind(() -> f.client.getRole("no-such-role")));
        }
    }

    @Test
    void userLookupFindsOrReturnsEmpty() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            assertEquals("Suspended", f.client.findUserById("pay.approver3").orElseThrow().statusEnum());
            assertTrue(f.client.findUserById("user-deleted-001").isEmpty());
        }
    }

    @Test
    void tokenIsRequestedOnceAndReused() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.client.findRolesByNamePattern(PATTERN, 1000, 10);
            f.client.getRoleMembers("role-fin");

            assertEquals(1, f.mock.requestCount(MockCyberArkServer.TOKEN));
        }
    }

    @Test
    void wrongSecretIsAnAuthenticationFailure() {
        try (MockFixture f = MockFixture.startWithSecret(SampleData.demo(), "wrong-secret")) {
            CyberArkApiException e = assertThrows(CyberArkApiException.class,
                    () -> f.client.findRolesByNamePattern(PATTERN, 1000, 10));

            assertEquals(CyberArkApiException.Kind.AUTHENTICATION, e.kind());
            assertEquals(401, e.httpStatus());
            assertFalse(e.getMessage().contains("wrong-secret"));
        }
    }

    @Test
    void revokedTokenIsRenewedOnceAndTheCallSucceeds() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.client.findRolesByNamePattern(PATTERN, 1000, 10);
            f.mock.revokeTokens();

            assertEquals(5, f.client.findRolesByNamePattern(PATTERN, 1000, 10).roles().size());
            assertEquals(2, f.mock.requestCount(MockCyberArkServer.TOKEN));
        }
    }

    @Test
    void persistent401And403AreAuthenticationFailures() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.GET_ROLE_MEMBERS, Fault.HTTP_401);
            assertEquals(CyberArkApiException.Kind.AUTHENTICATION, failureKind(() -> f.client.getRoleMembers("role-fin")));

            f.mock.fail(MockCyberArkServer.GET_ROLE_MEMBERS, Fault.HTTP_403);
            CyberArkApiException e = assertThrows(CyberArkApiException.class, () -> f.client.getRoleMembers("role-fin"));
            assertEquals(CyberArkApiException.Kind.AUTHENTICATION, e.kind());
            assertEquals(403, e.httpStatus());
        }
    }

    @Test
    void serverErrorIsAnHttpStatusFailure() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.REDROCK_ROLE, Fault.HTTP_500);
            CyberArkApiException e = assertThrows(CyberArkApiException.class,
                    () -> f.client.findRolesByNamePattern(PATTERN, 1000, 10));

            assertEquals(CyberArkApiException.Kind.HTTP_STATUS, e.kind());
            assertEquals(500, e.httpStatus());
        }
    }

    @Test
    void successFalseAndMalformedJsonAreReported() {
        try (MockFixture f = MockFixture.start(SampleData.demo())) {
            f.mock.fail(MockCyberArkServer.REDROCK_ROLE, Fault.SUCCESS_FALSE);
            assertEquals(CyberArkApiException.Kind.API_FAILURE, failureKind(() -> f.client.findRolesByNamePattern(PATTERN, 1000, 10)));

            f.mock.fail(MockCyberArkServer.REDROCK_USER, Fault.MALFORMED_JSON);
            assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE, failureKind(() -> f.client.findUserById("fin.approver1")));
        }
    }

    @Test
    void unreachableServerIsATransportFailure() {
        MockFixture f = MockFixture.start(SampleData.demo());
        f.close();
        assertEquals(CyberArkApiException.Kind.TRANSPORT,
                failureKind(() -> f.client.findRolesByNamePattern(PATTERN, 1000, 10)));
    }
}
