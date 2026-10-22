package com.keyforge.cyberarkpoc.check;

import com.keyforge.cyberarkpoc.client.CyberArkClient;
import com.keyforge.cyberarkpoc.model.Policy;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Use case 2: list every SIA/SCA access policy whose status is Error or Warning.
 *
 * <p>Status values come from the official SDK. A status outside that list (or a missing one) is not
 * flagged but reported separately, so an unexpected value is visible instead of silently passing.
 * Any API failure propagates as an exception.
 */
public final class PolicyHealthCheck {

    /** From the SDK's allowed values for {@code metadata.status.status}. */
    public static final Set<String> KNOWN_STATUSES =
            Set.of("active", "suspended", "expired", "validating", "error", "warning");
    public static final Set<String> FLAGGED_STATUSES = Set.of("error", "warning");

    private final CyberArkClient client;

    public PolicyHealthCheck(CyberArkClient client) {
        this.client = client;
    }

    public PolicyHealthReport run() {
        List<Policy> policies = client.listPolicies();
        List<Policy> flagged = new ArrayList<>();
        List<Policy> unrecognised = new ArrayList<>();
        for (Policy policy : policies) {
            String status = policy.status() == null ? "" : policy.status().trim().toLowerCase(Locale.ROOT);
            if (FLAGGED_STATUSES.contains(status)) {
                flagged.add(policy);
            } else if (!KNOWN_STATUSES.contains(status)) {
                unrecognised.add(policy);
            }
        }
        return new PolicyHealthReport(policies.size(), flagged, unrecognised);
    }

    public record PolicyHealthReport(int totalPolicies, List<Policy> flagged, List<Policy> unrecognisedStatus) {

        public boolean noPolicies() {
            return totalPolicies == 0;
        }
    }
}
