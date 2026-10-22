package com.keyforge.cyberarkpoc.model;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.Locale;

/**
 * One role member row ({@code Guid}, {@code Name}, {@code Type}; in the nested Roles API shape also
 * {@code IsEffective}, {@code OrgPath}, {@code OrgId}). {@code raw} is the row exactly as returned, kept for storage.
 */
public record RoleMember(String id, String name, Type type, String rawType, JsonNode raw) {

    public enum Type {
        USER, GROUP, ROLE, UNKNOWN;

        /**
         * {@code User} is documented; {@code Group} and {@code Role} come from the official SDK, which upper-cases the
         * wire value, so the wire casing is unknown: match case-insensitively.
         */
        public static Type fromWire(String value) {
            if (value == null) {
                return UNKNOWN;
            }
            return switch (value.trim().toUpperCase(Locale.ROOT)) {
                case "USER" -> USER;
                case "GROUP" -> GROUP;
                case "ROLE" -> ROLE;
                default -> UNKNOWN;
            };
        }
    }
}
