package com.keyforge.cyberarkpoc.store;

import com.fasterxml.jackson.databind.JsonNode;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.List;
import java.util.StringJoiner;
import java.util.UUID;

/**
 * Stores the records of one CyberArk API in {@code <schema>.<table>}, e.g. {@code cyberark.pvwa_safe}, with one
 * column per documented response field under the same name.
 *
 * <p>Besides the response fields there are only {@code record_uuid} (a random UUID given to the row when it is first
 * stored, never changed) and {@code extracted_at}. The record's own CyberArk id field (e.g. {@code safeUrlId}) is
 * unique, so a re-run updates the existing row and keeps its {@code record_uuid}. A relationship record (e.g. a Safe
 * member) is identified by several fields together (e.g. {@code safeUrlId} + {@code memberId}).
 */
public final class RawRecordRepository {

    public enum Outcome { INSERTED, UPDATED }

    public static final String UUID_COLUMN = "record_uuid";

    private final String schema;
    private final String table;
    private final List<Column> columns;
    private final List<Column> keys;

    /**
     * @param table   plain table name, e.g. {@code pvwa_safe}
     * @param columns the documented response fields, in documentation order
     * @param keyName the field holding CyberArk's unique id of the record; must be one of {@code columns}
     */
    public RawRecordRepository(String schema, String table, List<Column> columns, String keyName) {
        this(schema, table, columns, List.of(keyName));
    }

    /** @param keyNames the fields that together identify a record; each must be one of {@code columns} */
    public RawRecordRepository(String schema, String table, List<Column> columns, List<String> keyNames) {
        if (!table.matches("[a-z][a-z0-9_]{0,50}")) {
            throw new IllegalArgumentException("bad table name " + table);
        }
        if (keyNames.isEmpty()) {
            throw new IllegalArgumentException("a table needs at least one key field");
        }
        this.schema = DbConfig.validateSchema(schema);
        this.table = this.schema + "." + table;
        this.columns = List.copyOf(columns);
        this.keys = keyNames.stream().map(k -> columns.stream().filter(c -> c.name().equals(k)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("key " + k + " is not a column"))).toList();
    }

    public String table() {
        return table;
    }

    public String createTableSql() {
        StringBuilder sb = new StringBuilder("CREATE TABLE IF NOT EXISTS ").append(table).append(" (\n");
        sb.append("    ").append(UUID_COLUMN).append(" uuid PRIMARY KEY");
        for (Column c : columns) {
            sb.append(",\n    ").append(c.sql()).append(' ').append(c.kind().ddlType);
            if (keys.contains(c)) {
                sb.append(keys.size() == 1 ? " NOT NULL UNIQUE" : " NOT NULL");
            }
        }
        sb.append(",\n    extracted_at timestamp with time zone NOT NULL DEFAULT now()");
        if (keys.size() > 1) {
            sb.append(",\n    UNIQUE (").append(keyList()).append(')');
        }
        sb.append("\n)");
        return sb.toString();
    }

    private String keyList() {
        StringJoiner names = new StringJoiner(", ");
        keys.forEach(k -> names.add(k.sql()));
        return names.toString();
    }

    /** A new random {@code record_uuid} is offered on every insert; on a conflict the existing row keeps its own. */
    public String upsertSql() {
        StringJoiner names = new StringJoiner(", ");
        StringJoiner values = new StringJoiner(", ");
        StringJoiner updates = new StringJoiner(", ");
        names.add(UUID_COLUMN);
        values.add("?::uuid");
        for (Column c : columns) {
            names.add(c.sql());
            values.add(c.kind().placeholder);
            if (!keys.contains(c)) {
                updates.add(c.sql() + " = EXCLUDED." + c.sql());
            }
        }
        names.add("extracted_at");
        values.add("now()");
        updates.add("extracted_at = now()");
        return "INSERT INTO " + table + " (" + names + ") VALUES (" + values + ") ON CONFLICT (" + keyList()
                + ") DO UPDATE SET " + updates + " RETURNING (xmax = 0)";
    }

    /** Creates the schema and table if absent. Never alters an existing table or its data. */
    public void ensureTable(Connection conn) throws SQLException {
        try (Statement st = conn.createStatement()) {
            st.execute("CREATE SCHEMA IF NOT EXISTS " + schema);
            st.execute(createTableSql());
        }
    }

    /**
     * Stores one record: each column gets the value of the response field with the same name (absent or null →
     * SQL NULL). A value of the wrong type (e.g. text in a number column) is refused with an
     * {@link IllegalArgumentException}, never stored as something else.
     */
    public Outcome upsert(Connection conn, JsonNode record) throws SQLException {
        for (Column k : keys) {
            JsonNode id = record.get(k.name());
            if (id == null || id.isNull() || id.asText().isBlank()) {
                throw new IllegalArgumentException("record has no " + k.name());
            }
        }
        try (PreparedStatement ps = conn.prepareStatement(upsertSql())) {
            int i = 1;
            ps.setString(i++, UUID.randomUUID().toString());
            for (Column c : columns) {
                bind(ps, i++, c, record.get(c.name()));
            }
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() && rs.getBoolean(1) ? Outcome.INSERTED : Outcome.UPDATED;
            }
        }
    }

    private static void bind(PreparedStatement ps, int index, Column c, JsonNode v) throws SQLException {
        if (v == null || v.isNull()) {
            ps.setNull(index, switch (c.kind()) {
                case BIGINT -> Types.BIGINT;
                case BOOLEAN -> Types.BOOLEAN;
                default -> Types.VARCHAR;
            });
            return;
        }
        switch (c.kind()) {
            case TEXT -> ps.setString(index, v.isValueNode() ? v.asText() : v.toString());
            case JSONB -> ps.setString(index, v.toString());
            case BIGINT -> {
                if (v.isIntegralNumber() && v.canConvertToLong()) {
                    ps.setLong(index, v.longValue());
                } else if (v.isTextual() && v.asText().trim().matches("-?\\d{1,18}")) {
                    ps.setLong(index, Long.parseLong(v.asText().trim()));
                } else {
                    throw new IllegalArgumentException(c.name() + " is not a whole number: " + v.getNodeType());
                }
            }
            case BOOLEAN -> {
                if (v.isBoolean()) {
                    ps.setBoolean(index, v.booleanValue());
                } else if (v.isTextual() && v.asText().matches("(?i)true|false")) {
                    ps.setBoolean(index, Boolean.parseBoolean(v.asText()));
                } else {
                    throw new IllegalArgumentException(c.name() + " is not true/false: " + v.getNodeType());
                }
            }
        }
    }
}
