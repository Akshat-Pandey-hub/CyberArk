package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.model.CyberArkUser;
import com.keyforge.cyberarkpoc.model.Role;
import com.keyforge.cyberarkpoc.model.RoleDetails;
import com.keyforge.cyberarkpoc.model.RoleMember;

import java.util.ArrayList;
import java.util.List;

/**
 * Parses Identity responses per docs/API_CONTRACT.md.
 *
 * <ul>
 *   <li>Redrock (official "Use queries"): {@code {"success": .., "Result": {"Count", "FullCount", "Results":
 *       [{"Row": {..}}]}}}.</li>
 *   <li>Role members, two documented shapes: <b>flat</b> (data dictionary, {@code /SaasManage/GetRoleMembers}, and
 *       the SDK's reading of {@code /Roles/GetRoleMembers}): the Redrock envelope with one {@code Row} object per
 *       member; <b>nested</b> (Roles API reference example for {@code /Roles/GetRoleMembers}):
 *       {@code {"Result": {"success": .., "IsSoftError": .., "Result": {"Results": [{"Row": [{..}, ..]}],
 *       "FullCount"}}}}, where each {@code Row} is an array of members.</li>
 * </ul>
 *
 * <p>Anything that is neither documented shape, a missing {@code Results} array, or a {@code Row} of the wrong kind
 * is an {@code INVALID_RESPONSE}; it is never read as an empty list.
 */
public final class IdentityResponses {

    private IdentityResponses() {
    }

    /** Rows of one Redrock page and the totals the page reported ({@code null} when absent). */
    public record RedrockPage(List<JsonNode> rows, Integer count, Integer fullCount) {
    }

    /**
     * The members of one role as one response reported them.
     *
     * @param members       the members, in response order (duplicates kept, so the caller can report them)
     * @param reportedTotal {@code FullCount} when the response has it, else {@code null}
     * @param softError     the nested shape's {@code IsSoftError} was {@code true} (meaning undocumented)
     * @param shape         {@code flat} or {@code nested}
     */
    public record MemberList(List<RoleMember> members, Integer reportedTotal, boolean softError, String shape) {
    }

    /** The {@code Result} object of a flat envelope, after checking {@code success}. */
    public static JsonNode result(String endpoint, JsonNode root) {
        if (root == null || !root.isObject()) {
            throw invalid(endpoint, "response is not a JSON object");
        }
        return checkedResult(endpoint, root);
    }

    /** {@code node.success} must be a boolean {@code true}, and {@code node.Result} an object. */
    private static JsonNode checkedResult(String endpoint, JsonNode node) {
        JsonNode success = node.get("success");
        if (success == null || !success.isBoolean()) {
            throw invalid(endpoint, "missing boolean 'success'");
        }
        if (!success.asBoolean()) {
            String message = Json.text(node, "Message");
            throw new CyberArkApiException(CyberArkApiException.Kind.API_FAILURE, endpoint, 200,
                    message == null ? "success=false" : "success=false: " + message);
        }
        JsonNode result = node.get("Result");
        if (result == null || !result.isObject()) {
            throw invalid(endpoint, "missing object 'Result'");
        }
        return result;
    }

    /** The {@code Results} array of a result object; it must be present (it may be empty). */
    private static JsonNode resultsArray(String endpoint, JsonNode result) {
        JsonNode results = result.get("Results");
        if (results == null || !results.isArray()) {
            throw invalid(endpoint, "'Result.Results' is missing or not an array");
        }
        return results;
    }

    /** The {@code Row} objects of {@code Result.Results}. */
    public static List<JsonNode> rows(String endpoint, JsonNode root) {
        return page(endpoint, root).rows();
    }

    /** One Redrock page: its rows, {@code Count} and {@code FullCount}. */
    public static RedrockPage page(String endpoint, JsonNode root) {
        JsonNode result = result(endpoint, root);
        List<JsonNode> rows = new ArrayList<>();
        for (JsonNode item : resultsArray(endpoint, result)) {
            JsonNode row = item.get("Row");
            if (row == null || !row.isObject()) {
                throw invalid(endpoint, "an item of 'Result.Results' has no object 'Row'");
            }
            rows.add(row);
        }
        return new RedrockPage(rows, intOrNull(result.get("Count")), intOrNull(result.get("FullCount")));
    }

    public static List<Role> roles(String endpoint, JsonNode root) {
        return roles(endpoint, rows(endpoint, root));
    }

    public static List<Role> roles(String endpoint, List<JsonNode> rows) {
        List<Role> roles = new ArrayList<>();
        for (JsonNode row : rows) {
            roles.add(new Role(requiredText(endpoint, row, "ID"), Json.text(row, "Name"), Json.text(row, "Description"),
                    Json.text(row, "RoleType"), row));
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

    /** Role members in either documented shape (see the class comment). */
    public static MemberList roleMembers(String endpoint, JsonNode root) {
        if (root == null || !root.isObject()) {
            throw invalid(endpoint, "response is not a JSON object");
        }
        JsonNode container;
        boolean nested;
        boolean softError = false;
        if (root.has("success")) {
            container = checkedResult(endpoint, root);
            nested = false;
        } else {
            JsonNode outer = root.get("Result");
            if (outer == null || !outer.isObject() || !outer.has("success")) {
                throw invalid(endpoint, "neither the flat nor the nested documented members shape");
            }
            container = checkedResult(endpoint, outer);
            nested = true;
            JsonNode soft = outer.get("IsSoftError");
            softError = soft != null && soft.isBoolean() && soft.asBoolean();
        }
        List<RoleMember> members = new ArrayList<>();
        for (JsonNode item : resultsArray(endpoint, container)) {
            JsonNode row = item.get("Row");
            if (!nested) {
                if (row == null || !row.isObject()) {
                    throw invalid(endpoint, "flat shape: an item of 'Result.Results' has no object 'Row'");
                }
                members.add(member(endpoint, row));
            } else {
                if (row == null || !row.isArray()) {
                    throw invalid(endpoint, "nested shape: an item of 'Result.Result.Results' has no array 'Row'");
                }
                for (JsonNode entry : row) {
                    if (!entry.isObject()) {
                        throw invalid(endpoint, "nested shape: a 'Row' entry is not an object");
                    }
                    members.add(member(endpoint, entry));
                }
            }
        }
        return new MemberList(members, intOrNull(container.get("FullCount")), softError, nested ? "nested" : "flat");
    }

    private static RoleMember member(String endpoint, JsonNode row) {
        String type = Json.text(row, "Type");
        return new RoleMember(requiredText(endpoint, row, "Guid"), Json.text(row, "Name"),
                RoleMember.Type.fromWire(type), type, row);
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
                    Json.text(row, "StatusEnum"),
                    row));
        }
        return users;
    }

    private static Integer intOrNull(JsonNode node) {
        return node != null && node.isNumber() && node.canConvertToInt() ? node.asInt() : null;
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
