package com.keyforge.cyberarkpoc.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.model.Policy;

import java.util.ArrayList;
import java.util.List;

/**
 * Parses one page of {@code GET /api/policies}: {@code {"results": [..], "nextToken": "..", "total": n}}
 * (field names from the official SDK models, camelCase on the wire; see docs/API_CONTRACT.md).
 */
public final class PolicyResponses {

    /** One page. {@code nextToken} is {@code null} on the last page. */
    public record Page(List<Policy> policies, String nextToken) {
    }

    private PolicyResponses() {
    }

    public static Page page(String endpoint, JsonNode root) {
        if (root == null || !root.isObject()) {
            throw invalid(endpoint, "response is not a JSON object");
        }
        JsonNode results = root.get("results");
        if (results == null || !results.isArray()) {
            // The SDK also stops with an error when 'results' is missing.
            throw invalid(endpoint, "missing array 'results'");
        }
        List<Policy> policies = new ArrayList<>();
        for (JsonNode item : results) {
            policies.add(policy(endpoint, item));
        }
        String nextToken = Json.text(root, "nextToken");
        return new Page(policies, nextToken == null || nextToken.isBlank() ? null : nextToken);
    }

    static Policy policy(String endpoint, JsonNode item) {
        JsonNode metadata = item == null ? null : item.get("metadata");
        if (metadata == null || !metadata.isObject()) {
            throw invalid(endpoint, "a policy has no object 'metadata'");
        }
        JsonNode status = metadata.get("status");
        JsonNode entitlement = metadata.get("policyEntitlement");
        JsonNode updatedOn = metadata.get("updatedOn");
        return new Policy(
                Json.text(metadata, "policyId"),
                Json.text(metadata, "name"),
                Json.text(status, "status"),
                Json.text(status, "statusCode"),
                Json.text(status, "statusDescription"),
                Json.text(entitlement, "targetCategory"),
                Json.text(entitlement, "locationType"),
                Json.text(entitlement, "policyType"),
                Json.text(updatedOn, "user"),
                Json.text(updatedOn, "time"));
    }

    private static CyberArkApiException invalid(String endpoint, String message) {
        return new CyberArkApiException(CyberArkApiException.Kind.INVALID_RESPONSE, endpoint, 200, message);
    }
}
