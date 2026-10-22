package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.model.CyberArkUser;
import com.keyforge.cyberarkpoc.model.Role;
import com.keyforge.cyberarkpoc.model.RoleDetails;
import com.keyforge.cyberarkpoc.model.RoleMember;

import java.util.ArrayList;
import java.util.List;

/**
 * Parses the Identity response envelope {@code {"success": .., "Result": {"Results": [{"Row": ..}]}}}
 * (verified in the official SDK; see docs/API_CONTRACT.md).
 */
public final class IdentityResponses {

    private IdentityResponses() {
    }

    /** The {@code Result} object, after checking {@code success}. */
    public static JsonNode result(String endpoint, JsonNode root) {
        if (root == null || !root.isObject()) {
            throw invalid(endpoint, "response is not a JSON object");
        }
        JsonNode success = root.get("success");
        if (success == null || !success.isBoolean()) {
            throw invalid(endpoint, "missing boolean 'success'");
        }
        if (!success.asBoolean()) {
            String message = Json.text(root, "Message");
            throw new CyberArkApiException(CyberArkApiException.Kind.API_FAILURE, endpoint, 200,
                    message == null ? "success=false" : "success=false: " + message);
        }
        JsonNode result = root.get("Result");
        if (result == null || !result.isObject()) {
            throw invalid(endpoint, "missing object 'Result'");
        }
        return result;
    }

    /**
     * The {@code Row} objects of {@code Result.Results}. A missing {@code Results} array means no rows,
     * as the SDK treats it when listing role members.
     */
    public static List<JsonNode> rows(String endpoint, JsonNode root) {
        JsonNode results = result(endpoint, root).get("Results");
        List<JsonNode> rows = new ArrayList<>();
        if (results == null || results.isNull()) {
            return rows;
        }
        if (!results.isArray()) {
            throw invalid(endpoint, "'Result.Results' is not an array");
        }
        for (JsonNode item : results) {
            JsonNode row = item.get("Row");
            if (row == null || !row.isObject()) {
                throw invalid(endpoint, "an item of 'Result.Results' has no object 'Row'");
            }
            rows.add(row);
        }
        return rows;
    }

    public static List<Role> roles(String endpoint, JsonNode root) {
        List<Role> roles = new ArrayList<>();
        for (JsonNode row : rows(endpoint, root)) {
            roles.add(new Role(requiredText(endpoint, row, "ID"), Json.text(row, "Name"), Json.text(row, "Description")));
        }
        return roles;
    }

    /**
     * The official GetRole schema shows {@code Result} without a {@code success} flag, so a missing
     * flag is accepted here; {@code success: false} is still a failure.
     */
    public static RoleDetails roleDetails(String endpoint, JsonNode root) {
        JsonNode result;
        if (root != null && root.isObject() && root.get("success") == null) {
            result = root.get("Result");
            if (result == null || !result.isObject()) {
                throw invalid(endpoint, "missing object 'Result'");
            }
        } else {
            result = result(endpoint, root);
        }
        String id = Json.text(result, "Uuid") != null ? Json.text(result, "Uuid") : Json.text(result, "ID");
        List<String> principals = new ArrayList<>();
        JsonNode list = result.get("Principals");
        if (list != null && list.isArray()) {
            list.forEach(p -> principals.add(p.isValueNode() ? p.asText() : p.toString()));
        }
        return new RoleDetails(id, Json.text(result, "Name"), Json.text(result, "Description"),
                Json.text(result, "RoleType"), principals);
    }

    public static List<RoleMember> roleMembers(String endpoint, JsonNode root) {
        List<RoleMember> members = new ArrayList<>();
        for (JsonNode row : rows(endpoint, root)) {
            String type = Json.text(row, "Type");
            members.add(new RoleMember(requiredText(endpoint, row, "Guid"), Json.text(row, "Name"),
                    RoleMember.Type.fromWire(type), type));
        }
        return members;
    }

    public static List<CyberArkUser> users(String endpoint, JsonNode root) {
        List<CyberArkUser> users = new ArrayList<>();
        for (JsonNode row : rows(endpoint, root)) {
            users.add(new CyberArkUser(
                    requiredText(endpoint, row, "ID"),
                    Json.text(row, "Username"),
                    Json.text(row, "DisplayName"),
                    Json.text(row, "Email"),
                    Json.text(row, "LastLogin"),
                    Json.text(row, "Status"),
                    Json.text(row, "StatusEnum")));
        }
        return users;
    }

    private static String requiredText(String endpoint, JsonNode row, String field) {
        String value = Json.text(row, field);
        if (value == null || value.isBlank()) {
            throw invalid(endpoint, "a row has no '" + field + "'");
        }
        return value;
    }

    private static CyberArkApiException invalid(String endpoint, String message) {
        return new CyberArkApiException(CyberArkApiException.Kind.INVALID_RESPONSE, endpoint, 200, message);
    }
}
