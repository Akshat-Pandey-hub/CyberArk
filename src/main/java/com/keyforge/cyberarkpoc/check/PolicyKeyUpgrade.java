package com.keyforge.cyberarkpoc.check;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * Moves the two Use Case 2 tables from the old key {@code policy_id} to {@code (policy_api, policy_id)}, so that a UAP
 * and an SCA policy with the same id can be stored side by side.
 *
 * <p>Earlier versions keyed {@code uap_policy} with a unique index on {@code policy_id} and
 * {@code uap_policy_health_result} with a unique constraint on {@code policy_id}. Every row they wrote also has
 * {@code policy_api} (it has been set on every row since Use Case 2 was added), so each row keeps its identity:
 * only the unique index or constraint is replaced, and no row is changed or deleted.
 *
 * <p>It also adds {@code missing_since} to {@code uap_policy_health_result} if absent (results tables of earlier
 * versions); existing rows keep NULL there, meaning "not marked missing".
 *
 * <p>Safe to run on every run: it does nothing once the old key is gone (or on a new table). It runs in one
 * transaction under the same per-table locks as the table preparation, so the old key is never dropped without the
 * new one in place. If a row had no {@code policy_api}, its API could not be known: then nothing is changed and the
 * run fails with an explicit error instead of guessing.
 */
final class PolicyKeyUpgrade {

    private PolicyKeyUpgrade() {
    }

    /** Upgrades both tables if they still have the old key; returns what was changed (empty when nothing was). */
    static List<String> upgrade(Connection conn, String schema) throws SQLException {
        List<String> changes = new ArrayList<>();
        boolean autoCommit = conn.getAutoCommit();
        conn.setAutoCommit(false);
        try {
            for (String table : List.of(PolicyHealthRun.POLICY_TABLE, PolicyHealthRun.RESULT_TABLE)) {
                try (PreparedStatement lock = conn.prepareStatement("SELECT pg_advisory_xact_lock(hashtext(?))")) {
                    lock.setString(1, schema + "." + table);
                    lock.executeQuery().close();
                }
            }
            upgradeTable(conn, schema, PolicyHealthRun.POLICY_TABLE, false, changes);
            upgradeTable(conn, schema, PolicyHealthRun.RESULT_TABLE, true, changes);
            addMissingSince(conn, schema, changes);
            conn.commit();
            return changes;
        } catch (SQLException | RuntimeException e) {
            conn.rollback();
            throw e;
        } finally {
            conn.setAutoCommit(autoCommit);
        }
    }

    /** Adds the nullable {@code missing_since} column to an existing results table; no row is changed. */
    private static void addMissingSince(Connection conn, String schema, List<String> changes) throws SQLException {
        String sql = "SELECT 1 FROM information_schema.columns WHERE table_schema = ? AND table_name = ? "
                + "AND column_name = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, schema);
            ps.setString(2, PolicyHealthRun.RESULT_TABLE);
            ps.setString(3, PolicyHealthRun.MISSING_SINCE);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return;
                }
            }
        }
        try (Statement st = conn.createStatement()) {
            st.execute("ALTER TABLE " + schema + "." + PolicyHealthRun.RESULT_TABLE + " ADD COLUMN IF NOT EXISTS \""
                    + PolicyHealthRun.MISSING_SINCE + "\" timestamp with time zone");
        }
        changes.add(PolicyHealthRun.RESULT_TABLE + ": added " + PolicyHealthRun.MISSING_SINCE
                + " (NULL on every existing row)");
    }

    /** A unique index (or the index of a unique constraint) whose only column is {@code policy_id}. */
    private record OldKey(String index, String constraint) {
    }

    private static void upgradeTable(Connection conn, String schema, String table, boolean constraintStyle,
                                     List<String> changes) throws SQLException {
        List<OldKey> old = oldKeys(conn, schema, table);
        if (old.isEmpty()) {
            return; // a new table, or already upgraded
        }
        String qualified = schema + "." + table;
        try (Statement st = conn.createStatement()) {
            // a table whose only run stored no policy may lack the column; it then holds no rows without an API
            st.execute("ALTER TABLE " + qualified + " ADD COLUMN IF NOT EXISTS \"policy_api\" text");
            try (ResultSet rs = st.executeQuery("SELECT count(*) FROM " + qualified
                    + " WHERE \"policy_api\" IS NULL OR btrim(\"policy_api\") = ''")) {
                rs.next();
                long missing = rs.getLong(1);
                if (missing > 0) {
                    throw new SQLException(qualified + ": " + missing + " row(s) have no policy_api, so the move to the "
                            + "(policy_api, policy_id) key cannot tell which API they came from; nothing was changed. "
                            + "Set policy_api ('uap' or 'sca') on those rows, then run again");
                }
            }
            for (OldKey key : old) {
                if (key.constraint() != null) {
                    st.execute("ALTER TABLE " + qualified + " DROP CONSTRAINT \"" + key.constraint() + "\"");
                } else {
                    st.execute("DROP INDEX " + schema + ".\"" + key.index() + "\"");
                }
            }
            if (constraintStyle) {
                // as a new uap_policy_health_result is created: both key columns NOT NULL, UNIQUE (policy_api, policy_id)
                st.execute("ALTER TABLE " + qualified + " ALTER COLUMN \"policy_api\" SET NOT NULL");
                st.execute("ALTER TABLE " + qualified + " ADD UNIQUE (\"policy_api\", \"policy_id\")");
            } else {
                // the index the generic record store keeps on its key fields, under its usual name
                st.execute("CREATE UNIQUE INDEX \"" + table + "_cyberark_id_key\" ON " + qualified
                        + " (\"policy_api\", \"policy_id\")");
            }
        }
        changes.add(table + ": unique key moved from (policy_id) to (policy_api, policy_id); no row changed");
    }

    private static List<OldKey> oldKeys(Connection conn, String schema, String table) throws SQLException {
        String sql = "SELECT ci.relname, con.conname FROM pg_index i "
                + "JOIN pg_class c ON c.oid = i.indrelid JOIN pg_namespace n ON n.oid = c.relnamespace "
                + "JOIN pg_class ci ON ci.oid = i.indexrelid "
                + "LEFT JOIN pg_constraint con ON con.conindid = i.indexrelid AND con.conrelid = c.oid "
                + "WHERE n.nspname = ? AND c.relname = ? AND i.indisunique AND NOT i.indisprimary "
                + "AND (SELECT array_agg(a.attname::text) FROM pg_attribute a "
                + "WHERE a.attrelid = c.oid AND a.attnum = ANY(i.indkey)) = ARRAY['policy_id']";
        List<OldKey> keys = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, schema);
            ps.setString(2, table);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    keys.add(new OldKey(rs.getString(1), rs.getString(2)));
                }
            }
        }
        return keys;
    }
}
