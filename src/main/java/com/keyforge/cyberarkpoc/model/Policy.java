package com.keyforge.cyberarkpoc.model;

/** The parts of an Access Control Policy that the policy-health check needs (fields per the SDK). */
public record Policy(
        String policyId,
        String name,
        String status,
        String statusCode,
        String statusDescription,
        String targetCategory,
        String locationType,
        String policyType,
        String updatedBy,
        String updatedAt) {
}
