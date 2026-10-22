package com.keyforge.cyberarkpoc.model;

/**
 * A row from the Redrock {@code User} table (columns per the official data dictionary).
 *
 * <p>{@code statusEnum} is the {@code StatusEnum} column, documented as one of Created, Suspended,
 * Invited or Active; eligibility decisions use it. {@code status} is the localized {@code Status}
 * column (e.g. "Not Invited" for StatusEnum "Created"), kept for display only. Either is {@code null}
 * when absent.
 */
public record CyberArkUser(
        String id,
        String username,
        String displayName,
        String email,
        String lastLogin,
        String status,
        String statusEnum) {
}
