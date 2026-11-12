package com.keyforge.cyberarkpoc.check;

import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.config.PolicyConfig.Api;

import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Use Case 2: the outcome of one policy, from its documented status (docs/API_CONTRACT.md, Use Case 2).
 *
 * <ul>
 *   <li>UAP (Access Control Policies), {@code metadata.status.status}, schema {@code PolicyStatus}: Active, Suspended,
 *       Expired, Validating, Error, Warning; detail in {@code statusCode} / {@code statusDescription}</li>
 *   <li>SCA Policies API, {@code status} (integer): Active = 1, Expired = 3, Error = 4, Warning = 5, Validating = 6;
 *       detail in {@code faultCode} / {@code statusTooltipMessage}</li>
 * </ul>
 * {@link Outcome#FINDING} for Error and Warning, {@link Outcome#NO_FINDING} for the other documented statuses,
 * {@link Outcome#CANNOT_VERIFY} for a missing or undocumented status. Pure logic: no I/O.
 */
public final class PolicyHealthCheck {

    public enum Outcome { FINDING, NO_FINDING, CANNOT_VERIFY }

    /** UAP {@code PolicyStatus} allowed values, as documented (compared case-insensitively). */
    public static final Set<String> UAP_STATUSES =
            Set.of("Active", "Suspended", "Expired", "Validating", "Error", "Warning");
    /** SCA {@code status} values, as documented. 2 is not documented. */
    public static final Map<Integer, String> SCA_STATUSES =
            Map.of(1, "Active", 3, "Expired", 4, "Error", 5, "Warning", 6, "Validating");
    /** SCA {@code cloudProvider} values, as documented. */
    public static final Map<Integer, String> SCA_CLOUD_PROVIDERS = Map.of(0, "AWS", 1, "Google Cloud",
            2, "Azure resource", 3, "AWS IAM IDC", 4, "Microsoft Entra ID");
    static final Set<String> FLAGGED = Set.of("error", "warning");

    /**
     * One evaluated policy. {@code status} is the documented name (SCA adds the number: {@code "Error (4)"});
     * {@code statusCode} and {@code statusDescription} are UAP's fields or SCA's {@code faultCode} /
     * {@code statusTooltipMessage}.
     */
    public record PolicyResult(String policyId, String name, String status, String statusCode,
                               String statusDescription, String targetCategory, String locationType,
                               Outcome outcome, String reason) {
    }

    private PolicyHealthCheck() {
    }

    public static PolicyResult evaluate(Api api, JsonNode policy) {
        return api == Api.SCA ? sca(policy) : uap(policy);
    }

    private static PolicyResult uap(JsonNode policy) {
        JsonNode metadata = policy.get("metadata");
        if (metadata == null || !metadata.isObject()) {
            return new PolicyResult(null, null, null, null, null, null, null, Outcome.CANNOT_VERIFY,
                    "the policy has no 'metadata' object, so its status is unknown");
        }
        JsonNode statusObject = metadata.get("status");
        JsonNode entitlement = metadata.get("policyEntitlement");
        String id = text(metadata, "policyId");
        String name = text(metadata, "name");
        String code = text(statusObject, "statusCode");
        String description = text(statusObject, "statusDescription");
        String category = text(entitlement, "targetCategory");
        String location = text(entitlement, "locationType");
        JsonNode value = statusObject == null ? null : statusObject.get("status");
        if (value == null || value.isNull() || (value.isTextual() && value.asText().isBlank())) {
            return new PolicyResult(id, name, null, code, description, category, location, Outcome.CANNOT_VERIFY,
                    "the policy has no status");
        }
        if (!value.isTextual()) {
            return new PolicyResult(id, name, value.toString(), code, description, category, location,
                    Outcome.CANNOT_VERIFY, "undocumented status value " + value);
        }
        String status = value.asText().trim();
        String documented = UAP_STATUSES.stream().filter(s -> s.equalsIgnoreCase(status)).findFirst().orElse(null);
        if (documented == null) {
            return new PolicyResult(id, name, status, code, description, category, location, Outcome.CANNOT_VERIFY,
                    "undocumented status '" + status + "'");
        }
        return result(id, name, documented, documented, code, description, category, location);
    }

    private static PolicyResult sca(JsonNode policy) {
        String id = text(policy, "policyId");
        String name = text(policy, "name");
        JsonNode fault = policy.get("faultCode");
        String code = fault == null || fault.isNull() ? null : fault.asText();
        String description = text(policy, "statusTooltipMessage");
        JsonNode provider = policy.get("cloudProvider");
        String location = provider == null || provider.isNull() ? null
                : provider.canConvertToInt() && SCA_CLOUD_PROVIDERS.containsKey(provider.asInt())
                ? SCA_CLOUD_PROVIDERS.get(provider.asInt()) : provider.asText();
        JsonNode value = policy.get("status");
        if (value == null || value.isNull()) {
            return new PolicyResult(id, name, null, code, description, null, location, Outcome.CANNOT_VERIFY,
                    "the policy has no status");
        }
        if (!value.isIntegralNumber() || !value.canConvertToInt() || !SCA_STATUSES.containsKey(value.asInt())) {
            return new PolicyResult(id, name, value.asText(), code, description, null, location,
                    Outcome.CANNOT_VERIFY, "undocumented status value " + value);
        }
        String documented = SCA_STATUSES.get(value.asInt());
        return result(id, name, documented, documented + " (" + value.asInt() + ")", code, description, null,
                location);
    }

    /** The field as text, or {@code null} when it or its parent is absent or JSON null. */
    private static String text(JsonNode node, String field) {
        JsonNode value = node == null ? null : node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    private static PolicyResult result(String id, String name, String documented, String shown, String code,
                                       String description, String category, String location) {
        if (FLAGGED.contains(documented.toLowerCase(Locale.ROOT))) {
            String detail = (code == null ? "" : code) + (code != null && description != null ? " - " : "")
                    + (description == null ? "" : description);
            return new PolicyResult(id, name, shown, code, description, category, location, Outcome.FINDING,
                    "status " + documented
                            + (detail.isEmpty() ? " (no status code or description returned)" : ": " + detail));
        }
        return new PolicyResult(id, name, shown, code, description, category, location, Outcome.NO_FINDING,
                "status " + documented);
    }
}
