package com.keyforge.cyberarkpoc.store;

import com.fasterxml.jackson.databind.JsonNode;

import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringJoiner;
import java.util.UUID;

/**
 * Stores CyberArk records in {@code <schema>.<table>} with one column per top-level field <b>of the records actually
 * received</b>, under the field's exact name and letter case. Nothing is mapped by hand, so an additional, renamed or
 * differently-cased field is stored instead of dropped.
 *
 * <ul>
 *   <li>Column types follow the values: true/false {@code boolean}, whole numbers {@code bigint}, other numbers
 *       {@code numeric}, strings {@code text}, objects and arrays {@code jsonb}. A text value is never converted into
 *       a number or a date.</li>
 *   <li>When values of one field disagree (across records or across runs), the column is widened so every value
 *       fits: {@code bigint}+{@code numeric} to {@code numeric}; a boolean or number with a different scalar to
 *       {@code text}; anything with an object or array to {@code jsonb}. A record is never rejected because of a
 *       type. A column created while only {@code null} was seen is {@code text} and takes the first real type as
 *       long as it holds no value yet.</li>
 *   <li>A missing field and an explicit {@code null} are both stored as SQL {@code NULL}.</li>
 *   <li>Fixed service columns: {@code record_uuid} (a random UUID, kept on re-runs) and {@code extracted_at}. The
 *       record's CyberArk id field(s) carry a unique index, so a re-run updates the existing row.</li>
 *   <li>A field that cannot be a column (an empty name, a name longer than PostgreSQL's 63-byte limit, or the name of
 *       a service column) is kept in {@code _extra_fields} ({@code jsonb}) under its original name.</li>
 * </ul>
 *
 * <p>Schema changes run in one transaction under a per-table advisory lock, so two runs cannot alter the same table
 * at the same time, and a failure leaves the table as it was. They need the database user to own the table (the
 * service creates it) or have the right to alter it.
 */
public final class GenericRecordStore {

    public enum Outcome { INSERTED, UPDATED }

    public static final String UUID_COLUMN = "record_uuid";
    public static final String EXTRACTED_AT = "extracted_at";
    public static final String EXTRA_COLUMN = "_extra_fields";
    static final Set<String> SERVICE_COLUMNS = Set.of(UUID_COLUMN, EXTRACTED_AT, EXTRA_COLUMN);
    static final int MAX_NAME_BYTES = 63;

    /** Column types in widening order; {@link #join} gives the narrowest type that holds both. */
    public enum Kind {
        BOOLEAN("boolean"), BIGINT("bigint"), NUMERIC("numeric"), TEXT("text"), JSONB("jsonb");

        public final String ddl;

        Kind(String ddl) {
            this.ddl = ddl;
        }

        static Kind fromDataType(String dataType) {
            return switch (dataType) {
                case "boolean" -> BOOLEAN;
                case "bigint", "integer", "smallint" -> BIGINT;
                case "numeric", "double precision", "real" -> NUMERIC;
                case "jsonb", "json" -> JSONB;
                default -> TEXT;
            };
        }
    }

    /** The type of one JSON value, or {@code null} for JSON null / missing. */
    public static Kind kindOf(JsonNode value) {
        if (value == null || value.isNull() || value.isMissingNode()) {
            return null;
        }
        if (value.isBoolean()) {
            return Kind.BOOLEAN;
        }
        if (value.isIntegralNumber()) {
            return value.canConvertToLong() ? Kind.BIGINT : Kind.NUMERIC;
        }
        if (value.isNumber()) {
            return Kind.NUMERIC;
        }
        if (value.isTextual()) {
            return Kind.TEXT;
        }
        return Kind.JSONB;
    }

    /** The narrowest type that holds values of both types ({@code null} is "no value seen"). */
    public static Kind join(Kind a, Kind b) {
        if (a == null) {
            return b;
        }
        if (b == null || a == b) {
            return a;
        }
        if (a == Kind.JSONB || b == Kind.JSONB) {
            return Kind.JSONB;
        }
        boolean numeric = (a == Kind.BIGINT || a == Kind.NUMERIC) && (b == Kind.BIGINT || b == Kind.NUMERIC);
        return numeric ? Kind.NUMERIC : Kind.TEXT;
    }

    /**
     * The columns after {@link #prepare}: every data column with its type, and the schema changes made.
     *
     * @param columns     data columns in table order (without the service columns)
     * @param changes     e.g. {@code added "safeName" text}, {@code widened "x" bigint -> text}
     */
    public record Prepared(Map<String, Kind> columns, List<String> changes) {
    }

    private final String schema;
    private final String tableName;
    private final String table;
    private final List<String> keyFields;

    /**
     * @param table     plain table name, e.g. {@code pvwa_safe}
     * @param keyFields the field(s) holding CyberArk's id of a record (a unique index is kept on them)
     */
    public GenericRecordStore(String schema, String table, List<String> keyFields) {
        if (!table.matches("[a-z][a-z0-9_]{0,50}")) {
            throw new IllegalArgumentException("bad table name " + table);
        }
        if (keyFields.isEmpty()) {
            throw new IllegalArgumentException("a table needs at least one key field");
        }
        for (String key : keyFields) {
            if (!columnable(key)) {
                throw new IllegalArgumentException("key field cannot be a column: " + key);
            }
        }
        this.schema = DbConfig.validateSchema(schema);
        this.tableName = table;
        this.table = this.schema + "." + table;
        this.keyFields = List.copyOf(keyFields);
    }

    public String table() {
        return table;
    }

    /** Creates the schema and the table with its service columns if absent. Never alters existing data. */
    public void ensureTable(Connection conn) throws SQLException {
        try (Statement st = conn.createStatement()) {
            st.execute("CREATE SCHEMA IF NOT EXISTS " + schema);
            st.execute("CREATE TABLE IF NOT EXISTS " + table + " (\n    " + UUID_COLUMN + " uuid PRIMARY KEY,\n    "
                    + EXTRACTED_AT + " timestamp with time zone NOT NULL DEFAULT now()\n)");
        }
    }

    /**
     * Makes the table able to hold every record: adds missing columns, widens columns whose type cannot hold a value,
     * and keeps a unique index on the key fields. One transaction, under a per-table advisory lock.
     */
    public Prepared prepare(Connection conn, List<JsonNode> records) throws SQLException {
        Map<String, Kind> needed = new LinkedHashMap<>();
        Map<String, Boolean> seen = new LinkedHashMap<>();
        boolean needsExtra = false;
        for (String key : keyFields) {
            seen.put(key, true);
        }
        for (JsonNode record : records) {
            Iterator<Map.Entry<String, JsonNode>> fields = record.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> f = fields.next();
                if (!columnable(f.getKey())) {
                    needsExtra = true;
                    continue;
                }
                seen.put(f.getKey(), true);
                needed.put(f.getKey(), join(needed.get(f.getKey()), kindOf(f.getValue())));
            }
        }
        boolean autoCommit = conn.getAutoCommit();
        conn.setAutoCommit(false);
        try {
            try (PreparedStatement lock = conn.prepareStatement("SELECT pg_advisory_xact_lock(hashtext(?))")) {
                lock.setString(1, table);
                lock.executeQuery().close();
            }
            Map<String, Kind> existing = existingColumns(conn);
            List<String> changes = new ArrayList<>();
            try (Statement st = conn.createStatement()) {
                for (String name : seen.keySet()) {
                    Kind want = needed.get(name);
                    Kind have = existing.get(name);
                    if (have == null) {
                        Kind create = want == null ? Kind.TEXT : want;
                        st.execute("ALTER TABLE " + table + " ADD COLUMN " + quote(name) + " " + create.ddl);
                        existing.put(name, create);
                        changes.add("added " + quote(name) + " " + create.ddl);
                    } else if (want != null && want != have
                            && (join(have, want) != have || holdsOnlyNulls(conn, name))) {
                        // A column without any value yet takes the new type as it is; otherwise it is widened.
                        Kind target = holdsOnlyNulls(conn, name) ? want : join(have, want);
                        st.execute("ALTER TABLE " + table + " ALTER COLUMN " + quote(name) + " TYPE " + target.ddl
                                + " USING " + conversion(name, have, target));
                        existing.put(name, target);
                        changes.add("widened " + quote(name) + " " + have.ddl + " -> " + target.ddl);
                    }
                }
                if (needsExtra && !existing.containsKey(EXTRA_COLUMN)) {
                    st.execute("ALTER TABLE " + table + " ADD COLUMN " + EXTRA_COLUMN + " jsonb");
                    existing.put(EXTRA_COLUMN, Kind.JSONB);
                    changes.add("added " + EXTRA_COLUMN + " jsonb");
                }
                if (!hasUniqueIndexOnKeys(conn)) {
                    StringJoiner keys = new StringJoiner(", ");
                    keyFields.forEach(k -> keys.add(quote(k)));
                    st.execute("CREATE UNIQUE INDEX " + tableName + "_cyberark_id_key ON " + table + " (" + keys + ")");
                    changes.add("unique index on " + keys);
                }
            }
            conn.commit();
            Map<String, Kind> data = new LinkedHashMap<>(existing);
            data.remove(UUID_COLUMN);
            data.remove(EXTRACTED_AT);
            return new Prepared(data, changes);
        } catch (SQLException | RuntimeException e) {
            conn.rollback();
            throw e;
        } finally {
            conn.setAutoCommit(autoCommit);
        }
    }

    /**
     * Stores one record: each column gets the field of the same name (absent or null: SQL NULL). Every data column of
     * the table is written, so a field that disappeared from CyberArk is cleared, not left stale.
     */
    public Outcome upsert(Connection conn, Prepared prepared, JsonNode record) throws SQLException {
        for (String key : keyFields) {
            JsonNode id = record.get(key);
            if (id == null || id.isNull() || (id.isTextual() && id.asText().isBlank())) {
                throw new IllegalArgumentException("record has no " + key);
            }
        }
        List<String> names = new ArrayList<>(prepared.columns().keySet());
        StringJoiner cols = new StringJoiner(", ");
        StringJoiner values = new StringJoiner(", ");
        StringJoiner updates = new StringJoiner(", ");
        cols.add(UUID_COLUMN);
        values.add("?::uuid");
        for (String name : names) {
            Kind kind = prepared.columns().get(name);
            cols.add(quote(name));
            values.add(kind == Kind.JSONB ? "?::jsonb" : "?");
            if (!keyFields.contains(name)) {
                updates.add(quote(name) + " = EXCLUDED." + quote(name));
            }
        }
        cols.add(EXTRACTED_AT);
        values.add("now()");
        updates.add(EXTRACTED_AT + " = now()");
        StringJoiner keys = new StringJoiner(", ");
        keyFields.forEach(k -> keys.add(quote(k)));
        String sql = "INSERT INTO " + table + " (" + cols + ") VALUES (" + values + ") ON CONFLICT (" + keys
                + ") DO UPDATE SET " + updates + " RETURNING (xmax = 0)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            int i = 1;
            ps.setString(i++, UUID.randomUUID().toString());
            for (String name : names) {
                JsonNode value = name.equals(EXTRA_COLUMN) ? extraFields(record) : record.get(name);
                bind(ps, i++, prepared.columns().get(name), value);
            }
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() && rs.getBoolean(1) ? Outcome.INSERTED : Outcome.UPDATED;
            }
        }
    }

    /** The fields of {@code record} that cannot be columns, or {@code null} when there are none. */
    private static JsonNode extraFields(JsonNode record) {
        com.fasterxml.jackson.databind.node.ObjectNode extra = null;
        Iterator<Map.Entry<String, JsonNode>> fields = record.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> f = fields.next();
            if (!columnable(f.getKey())) {
                if (extra == null) {
                    extra = com.fasterxml.jackson.databind.node.JsonNodeFactory.instance.objectNode();
                }
                extra.set(f.getKey(), f.getValue());
            }
        }
        return extra;
    }

    /** Binds a value into a column whose type holds it (guaranteed by {@link #prepare}). */
    private static void bind(PreparedStatement ps, int i, Kind kind, JsonNode v) throws SQLException {
        if (v == null || v.isNull() || v.isMissingNode()) {
            ps.setNull(i, switch (kind) {
                case BOOLEAN -> Types.BOOLEAN;
                case BIGINT -> Types.BIGINT;
                case NUMERIC -> Types.NUMERIC;
                default -> Types.VARCHAR;
            });
            return;
        }
        switch (kind) {
            case BOOLEAN -> ps.setBoolean(i, v.booleanValue());
            case BIGINT -> ps.setLong(i, v.longValue());
            case NUMERIC -> ps.setBigDecimal(i, v.decimalValue());
            case TEXT -> ps.setString(i, v.isNumber() ? v.decimalValue().toPlainString() : v.asText());
            case JSONB -> ps.setString(i, v.toString());
        }
    }

    /** The SQL that converts a column from {@code from} to the wider {@code to}, without losing values. */
    private static String conversion(String name, Kind from, Kind to) {
        String col = quote(name);
        return switch (to) {
            case JSONB -> "to_jsonb(" + col + ")";
            case TEXT -> col + "::text";
            case NUMERIC -> col + "::numeric";
            default -> col + "::" + to.ddl; // only reached for a column that holds no value yet
        };
    }

    private boolean holdsOnlyNulls(Connection conn, String name) throws SQLException {
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("SELECT NOT EXISTS (SELECT 1 FROM " + table + " WHERE " + quote(name)
                     + " IS NOT NULL)")) {
            return rs.next() && rs.getBoolean(1);
        }
    }

    private Map<String, Kind> existingColumns(Connection conn) throws SQLException {
        Map<String, Kind> columns = new LinkedHashMap<>();
        try (PreparedStatement ps = conn.prepareStatement("SELECT column_name, data_type FROM information_schema.columns "
                + "WHERE table_schema = ? AND table_name = ? ORDER BY ordinal_position")) {
            ps.setString(1, schema);
            ps.setString(2, tableName);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    columns.put(rs.getString(1), Kind.fromDataType(rs.getString(2)));
                }
            }
        }
        return columns;
    }

    private boolean hasUniqueIndexOnKeys(Connection conn) throws SQLException {
        String sql = "SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid "
                + "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = ? AND c.relname = ? AND i.indisunique "
                + "AND (SELECT array_agg(a.attname::text ORDER BY a.attname::text) FROM pg_attribute a "
                + "WHERE a.attrelid = c.oid AND a.attnum = ANY(i.indkey)) = ?::text[]";
        List<String> sorted = new ArrayList<>(keyFields);
        sorted.sort(String::compareTo);
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, schema);
            ps.setString(2, tableName);
            Array keys = conn.createArrayOf("text", sorted.toArray());
            ps.setArray(3, keys);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    /** Whether a field name can be a column of its own. */
    static boolean columnable(String name) {
        return name != null && !name.isEmpty() && !SERVICE_COLUMNS.contains(name) && name.indexOf('\0') < 0
                && name.getBytes(java.nio.charset.StandardCharsets.UTF_8).length <= MAX_NAME_BYTES;
    }

    /** A quoted SQL identifier with the exact name; embedded quotes are doubled. */
    static String quote(String name) {
        return "\"" + name.replace("\"", "\"\"") + "\"";
    }
}
