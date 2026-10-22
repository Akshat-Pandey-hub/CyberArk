package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.model.RoleDetails;
import com.keyforge.cyberarkpoc.model.RoleMember;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Parsing rules on hand-written FABRICATED bodies (no HTTP). */
class ResponseParsingTest {

    private static JsonNode json(String text) {
        return Json.parse("test", 200, text);
    }

    private static CyberArkApiException.Kind kindOf(Runnable call) {
        return assertThrows(CyberArkApiException.class, call::run).kind();
    }

    @Test
    void identityRowsAreRead() {
        JsonNode body = json("""
                {"success": true, "Result": {"Count": 2, "Results": [
                  {"Row": {"Guid": "u1", "Name": "a@example.test", "Type": "User"}},
                  {"Row": {"Guid": "g1", "Name": "Group A", "Type": "GROUP"}}]}}""");

        List<RoleMember> members = IdentityResponses.roleMembers("test", body).members();

        assertEquals(2, members.size());
        assertEquals(RoleMember.Type.USER, members.get(0).type());
        assertEquals(RoleMember.Type.GROUP, members.get(1).type());
    }

    @Test
    void getRoleIsReadWithTheOfficialFieldNames() {
        // Shape of the official Roles API example (no 'success' flag).
        RoleDetails details = IdentityResponses.roleDetails("test", json("""
                {"Result": {"DirectoryServiceUuid": "d1", "Principals": ["u1", "u2"], "RoleType": "PrincipalList",
                  "Uuid": "r1", "ReadOnly": true, "Description": "desc", "Name": "Role One"}}"""));

        assertEquals("r1", details.id());
        assertEquals("Role One", details.name());
        assertEquals(List.of("u1", "u2"), details.principals());
    }

    @Test
    void getRoleWithSuccessFalseIsAnApiFailure() {
        assertEquals(CyberArkApiException.Kind.API_FAILURE, kindOf(() -> IdentityResponses.roleDetails("test",
                json("{\"success\": false, \"Result\": null, \"Message\": \"no role\"}"))));
    }

    @Test
    void missingResultsArrayIsInvalidNotAnEmptyList() {
        // Every official Redrock example has Results; a missing one is malformed, never "no rows".
        CyberArkApiException e = assertThrows(CyberArkApiException.class,
                () -> IdentityResponses.rows("test", json("{\"success\": true, \"Result\": {}}")));
        assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE, e.kind());
        assertTrue(IdentityResponses.rows("test", json("{\"success\": true, \"Result\": {\"Results\": []}}")).isEmpty());
    }

    @Test
    void successFalseIsAnApiFailure() {
        CyberArkApiException e = assertThrows(CyberArkApiException.class, () -> IdentityResponses.rows("test",
                json("{\"success\": false, \"Result\": null, \"Message\": \"denied\"}")));
        assertEquals(CyberArkApiException.Kind.API_FAILURE, e.kind());
        assertTrue(e.getMessage().contains("denied"));
    }

    @Test
    void brokenIdentityEnvelopesAreInvalid() {
        assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE,
                kindOf(() -> IdentityResponses.rows("test", json("{\"Result\": {}}"))));
        assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE,
                kindOf(() -> IdentityResponses.rows("test", json("{\"success\": true}"))));
        assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE,
                kindOf(() -> IdentityResponses.rows("test", json("{\"success\": true, \"Result\": {\"Results\": [{}]}}"))));
        assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE,
                kindOf(() -> IdentityResponses.roleMembers("test",
                        json("{\"success\": true, \"Result\": {\"Results\": [{\"Row\": {\"Name\": \"x\"}}]}}"))));
    }

    @Test
    void notJsonIsInvalid() {
        assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE, kindOf(() -> Json.parse("test", 200, "<html>")));
        assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE, kindOf(() -> Json.parse("test", 200, "")));
    }

    @Test
    void policyPageIsRead() {
        PolicyResponses.Page page = PolicyResponses.page("test", json("""
                {"results": [{"metadata": {"policyId": "p1", "name": "P1",
                   "status": {"status": "Error", "statusCode": "C1", "statusDescription": "D1"},
                   "policyEntitlement": {"targetCategory": "Cloud console", "locationType": "AWS", "policyType": "Recurring"},
                   "updatedOn": {"user": "u@example.test", "time": "2026-01-01T00:00:00"}}}],
                 "nextToken": "abc", "total": 1}"""));

        assertEquals("abc", page.nextToken());
        assertEquals("Error", page.policies().get(0).status());
        assertEquals("C1", page.policies().get(0).statusCode());
        assertEquals("AWS", page.policies().get(0).locationType());
        assertEquals("u@example.test", page.policies().get(0).updatedBy());
    }

    @Test
    void blankNextTokenEndsPaging() {
        assertNull(PolicyResponses.page("test", json("{\"results\": [], \"nextToken\": \"\"}")).nextToken());
        assertNull(PolicyResponses.page("test", json("{\"results\": []}")).nextToken());
    }

    @Test
    void brokenPolicyPagesAreInvalid() {
        assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE,
                kindOf(() -> PolicyResponses.page("test", json("{\"policies\": []}"))));
        assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE,
                kindOf(() -> PolicyResponses.page("test", json("{\"results\": [{\"name\": \"no metadata\"}]}"))));
    }

    @Test
    void policyWithoutStatusHasNullStatus() {
        PolicyResponses.Page page = PolicyResponses.page("test",
                json("{\"results\": [{\"metadata\": {\"policyId\": \"p1\", \"name\": \"P1\"}}]}"));
        assertNull(page.policies().get(0).status());
    }
}
