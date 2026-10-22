package com.keyforge.cyberarkpoc.model;

import java.util.Locale;

/** A GetRoleMembers row ({@code Guid}, {@code Name}, {@code Type}; verified in the SDK). */
public record RoleMember(String id, String name, Type type, String rawType) {

    public enum Type {
        USER, GROUP, ROLE, UNKNOWN;

        /** The SDK upper-cases the wire value, so the wire casing is unknown; match case-insensitively. */
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
