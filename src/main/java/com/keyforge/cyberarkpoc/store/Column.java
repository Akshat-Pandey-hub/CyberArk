package com.keyforge.cyberarkpoc.store;

/**
 * One table column, named exactly like the field in the CyberArk response (letter case kept, so the SQL name is
 * quoted, e.g. {@code "safeUrlId"}). Nested objects and arrays are stored as {@code jsonb}.
 */
public record Column(String name, Kind kind) {

    public enum Kind {
        TEXT("text", "?"),
        BIGINT("bigint", "?"),
        BOOLEAN("boolean", "?"),
        JSONB("jsonb", "?::jsonb");

        public final String ddlType;
        public final String placeholder;

        Kind(String ddlType, String placeholder) {
            this.ddlType = ddlType;
            this.placeholder = placeholder;
        }
    }

    public Column {
        if (!name.matches("[A-Za-z_][A-Za-z0-9_]{0,62}")) {
            throw new IllegalArgumentException("bad column name " + name);
        }
    }

    /** The quoted SQL identifier, e.g. {@code "safeUrlId"}. */
    public String sql() {
        return "\"" + name + "\"";
    }

    public static Column text(String name) { return new Column(name, Kind.TEXT); }
    public static Column bigint(String name) { return new Column(name, Kind.BIGINT); }
    public static Column bool(String name) { return new Column(name, Kind.BOOLEAN); }
    public static Column jsonb(String name) { return new Column(name, Kind.JSONB); }
}
