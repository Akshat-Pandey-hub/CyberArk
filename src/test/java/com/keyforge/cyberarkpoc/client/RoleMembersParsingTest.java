package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyforge.cyberarkpoc.client.IdentityResponses.MemberList;
import com.keyforge.cyberarkpoc.model.RoleMember;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The two documented role-members shapes (docs/API_CONTRACT.md §6) and the malformed responses that must fail
 * instead of reading as an empty membership.
 */
class RoleMembersParsingTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode json(String text) {
        try {
            return MAPPER.readTree(text);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static CyberArkApiException failure(String body) {
        return assertThrows(CyberArkApiException.class, () -> IdentityResponses.roleMembers("test", json(body)));
    }

    @Test
    void flatShapeIsRead() {
        MemberList list = IdentityResponses.roleMembers("test", json("""
                {"success": true, "Result": {"Count": 2, "FullCount": 2, "Results": [
                  {"Row": {"Guid": "u1", "Name": "a@example.test", "Type": "User"}},
                  {"Row": {"Guid": "r1", "Name": "Child", "Type": "Role"}}]}, "Message": null}"""));

        assertEquals("flat", list.shape());
        assertEquals(2, list.members().size());
        assertEquals(RoleMember.Type.ROLE, list.members().get(1).type());
        assertEquals(2, list.reportedTotal());
        assertFalse(list.softError());
        assertEquals("a@example.test", list.members().get(0).raw().get("Name").asText(), "raw row kept");
    }

    @Test
    void nestedShapeIsReadWithSeveralMembersInOneRowArray() {
        MemberList list = IdentityResponses.roleMembers("test", json("""
                {"Result": {"Result": {"Results": [{"Row": [
                    {"Guid": "u1", "Name": "a", "Type": "User", "IsEffective": true, "OrgPath": "", "OrgId": ""},
                    {"Guid": "g1", "Name": "G", "Type": "Group", "IsEffective": false}]}],
                  "count": 2, "FullCount": 2}, "success": true, "IsSoftError": false, "Message": null},
                 "Error": {}}"""));

        assertEquals("nested", list.shape());
        assertEquals(2, list.members().size());
        assertEquals(RoleMember.Type.GROUP, list.members().get(1).type());
        assertTrue(list.members().get(0).raw().get("IsEffective").asBoolean());
        assertEquals(2, list.reportedTotal());
        assertFalse(list.softError());
    }

    @Test
    void emptyResultsIsAnEmptyMembershipInEitherShape() {
        assertTrue(IdentityResponses.roleMembers("test",
                json("{\"success\": true, \"Result\": {\"Results\": []}}")).members().isEmpty());
        assertTrue(IdentityResponses.roleMembers("test",
                json("{\"Result\": {\"success\": true, \"Result\": {\"Results\": []}}}")).members().isEmpty());
    }

    @Test
    void failureEnvelopesAreApiFailuresInEitherShape() {
        CyberArkApiException flat = failure("{\"success\": false, \"Result\": null, \"Message\": \"role not found\"}");
        CyberArkApiException nested = failure("{\"Result\": {\"success\": false, \"Message\": \"Invalid role\"}}");

        assertEquals(CyberArkApiException.Kind.API_FAILURE, flat.kind());
        assertTrue(flat.getMessage().contains("role not found"));
        assertEquals(CyberArkApiException.Kind.API_FAILURE, nested.kind());
        assertTrue(nested.getMessage().contains("Invalid role"));
    }

    @Test
    void aRowOfTheWrongKindIsInvalidNotEmpty() {
        // Flat shape with an array Row, nested shape with an object Row, a nested entry that is not an object.
        assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE, failure("""
                {"success": true, "Result": {"Results": [{"Row": [{"Guid": "u1"}]}]}}""").kind());
        assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE, failure("""
                {"Result": {"success": true, "Result": {"Results": [{"Row": {"Guid": "u1"}}]}}}""").kind());
        assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE, failure("""
                {"Result": {"success": true, "Result": {"Results": [{"Row": ["u1"]}]}}}""").kind());
        assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE, failure("""
                {"success": true, "Result": {"Results": [{"NoRow": {}}]}}""").kind());
    }

    @Test
    void missingResultsOrGuidOrAnUnknownShapeIsInvalid() {
        assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE,
                failure("{\"success\": true, \"Result\": {\"Count\": 0}}").kind());
        assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE,
                failure("{\"Result\": {\"success\": true, \"Result\": {}}}").kind());
        assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE, failure("""
                {"success": true, "Result": {"Results": [{"Row": {"Name": "no guid", "Type": "User"}}]}}""").kind());
        assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE, failure("{\"Result\": {\"Results\": []}}").kind());
        assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE, failure("[]").kind());
        assertEquals(CyberArkApiException.Kind.INVALID_RESPONSE, failure("{\"success\": \"yes\", \"Result\": {}}").kind());
    }

    @Test
    void softErrorAndMissingFullCountAreReported() {
        MemberList list = IdentityResponses.roleMembers("test", json("""
                {"Result": {"success": true, "IsSoftError": true, "Result": {"Results": [
                  {"Row": [{"Guid": "u1", "Name": "a", "Type": "User"}]}]}}}"""));

        assertTrue(list.softError());
        assertNull(list.reportedTotal());
    }
}
