package com.keyforge.cyberarkpoc.model;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * A row from the Redrock {@code Role} table (official data dictionary: ID, Name, RoleType, ReadOnly, Description).
 * {@code roleType} is "PrincipalList, Everybody, or Script"; only a PrincipalList role's member list is its real
 * membership. {@code raw} is the row exactly as returned, kept for storage.
 */
public record Role(String id, String name, String description, String roleType, JsonNode raw) {

    /** The documented role type whose members are an explicit list. */
    public static final String PRINCIPAL_LIST = "PrincipalList";

    /** True only for a role documented to list its members explicitly. */
    public boolean hasExplicitMembers() {
        return roleType != null && roleType.trim().equalsIgnoreCase(PRINCIPAL_LIST);
    }
}
