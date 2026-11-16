package com.keyforge.cyberarkpoc.check;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.keyforge.cyberarkpoc.check.ApproverGroupCheck.ApproverGroupReport;
import com.keyforge.cyberarkpoc.check.ApproverGroupCheck.MemberResult;
import com.keyforge.cyberarkpoc.check.ApproverGroupCheck.MemberRows;
import com.keyforge.cyberarkpoc.check.ApproverGroupCheck.Outcome;
import com.keyforge.cyberarkpoc.check.ApproverGroupCheck.RoleResult;
import com.keyforge.cyberarkpoc.client.CyberArkApiException;
import com.keyforge.cyberarkpoc.client.CyberArkClient;
import com.keyforge.cyberarkpoc.client.SecretRedactor;
import com.keyforge.cyberarkpoc.config.ConfigException;
import com.keyforge.cyberarkpoc.model.CyberArkUser;
import com.keyforge.cyberarkpoc.model.RoleMember;
import com.keyforge.cyberarkpoc.store.Column;
import com.keyforge.cyberarkpoc.store.DbConfig;
import com.keyforge.cyberarkpoc.store.RawRecordRepository;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Runs Use Case 1 end to end: open the database, run {@link ApproverGroupCheck}, store what was read and the results,
 * and answer with one JSON summary (REST route {@code ispss/approver-groups}, CLI {@code ispss-approver-groups}).
 *
 * <p>Tables, in the PVWA convention (one column per field under its exact name, a random {@code record_uuid}, the
 * source id as the unique key, {@code extracted_at}):
 * <ul>
 *   <li>{@code ispss_role}: the Role table rows read (matching roles and expanded nested roles), key {@code ID}</li>
 *   <li>{@code ispss_role_member}: every member row a members call returned, key {@code role_id} + {@code Guid};
 *       {@code role_id} is ours (the role the list belongs to), the other columns are the API's</li>
 *   <li>{@code ispss_user}: the User rows looked up, key {@code ID}</li>
 *   <li>{@code ispss_approver_group_result}: the latest result per role, key {@code role_id} (our columns)</li>
 * </ul>
 * Tokens and credentials are never stored; every message is passed through {@link CyberArkClient#sanitize}.
 *
 * <p><b>Rows no longer returned.</b> {@code missing_since} (in {@code ispss_approver_group_result} and
 * {@code ispss_role_member}) is NULL while a row is returned; every normal upsert writes NULL there, so a row that comes
 * back is cleared on the same row. Rows are never deleted. After the run:
 * <ul>
 *   <li>roles: results of this run's {@code role_pattern} whose role was not found get {@code missing_since}, only if
 *       the role search was complete, reported a {@code FullCount} equal to the roles found, found at least one role,
 *       and every result row was stored. A role whose check failed (CHECK_FAILED) was still found, so it is present.</li>
 *   <li>members: each fetched member list on its own (direct and nested roles): stored members of that role not in the
 *       list get {@code missing_since}, only if that list reported a {@code FullCount} equal to its members, had no
 *       {@code IsSoftError} and no repeated member, and all its rows were stored.</li>
 * </ul>
 * "Missing" means "not returned by the latest qualifying read" (deleted, or no longer visible to the service user).
 *
 * <p><b>One run at a time.</b> A run holds a PostgreSQL session advisory lock on its one connection from before
 * CyberArk is called until it ends; a second run (in any process) fails at once.
 */
public final class ApproverGroupRun {

    public static final String COMMAND = "ispss-approver-groups";
    public static final String RESULT_TABLE = "ispss_approver_group_result";
    public static final String MEMBER_TABLE = "ispss_role_member";
    /** When a role result or member row was first not returned by a qualifying read; NULL while it is returned. */
    public static final String MISSING_SINCE = "missing_since";
    /** The run's advisory lock: (LOCK_SPACE, LOCK_KEY), held for the whole run. */
    public static final int LOCK_SPACE = 0x4B465543; // "KFUC", shared by the use-case run locks
    public static final int LOCK_KEY = 11;
    public static final String ALREADY_RUNNING = "another ispss-approver-groups run is already running (it holds "
            + "the PostgreSQL advisory lock); nothing was done. Run again when it has finished";

    public static final List<Column> ROLE_COLUMNS = List.of(
            Column.text("ID"), Column.text("Name"), Column.text("RoleType"), Column.bool("ReadOnly"),
            Column.text("Description"));
    public static final List<Column> ROLE_MEMBER_COLUMNS = List.of(
            Column.text("role_id"), Column.text("Guid"), Column.text("Name"), Column.text("Type"),
            Column.bool("IsEffective"), Column.text("OrgPath"), Column.text("OrgId"),
            // never in a member row, so every upsert writes NULL here: a returned member is not missing
            Column.timestamptz(MISSING_SINCE));
    public static final List<Column> USER_COLUMNS = List.of(
            Column.text("ID"), Column.text("Username"), Column.text("DisplayName"), Column.text("Email"),
            Column.text("LastLogin"), Column.text("Status"), Column.text("StatusEnum"));
    public static final List<Column> RESULT_COLUMNS = List.of(
            Column.text("role_id"), Column.text("role_name"), Column.text("outcome"),
            Column.bigint("direct_members"), Column.jsonb("direct_members_by_type"), Column.bigint("active_users"),
            Column.bool("total_threshold_met"), Column.bool("active_threshold_met"), Column.bigint("min_approvers"),
            Column.text("role_pattern"), Column.jsonb("reasons"), Column.jsonb("notes"), Column.jsonb("members"),
            Column.text("error"),
            // never in a result record, so every upsert writes NULL here: a role found again is not missing
            Column.timestamptz(MISSING_SINCE));

    /**
     * Check settings.
     *
     * @param rolePattern  Redrock {@code LIKE} pattern
     * @param minApprovers threshold for both direct members and verified active users
     * @param pageSize     Redrock {@code PageSize}
     */
    public record Settings(String rolePattern, int minApprovers, int pageSize, int maxPages) {

        public static final String ENV_PATTERN = "CYBERARK_APPROVER_ROLE_PATTERN";
        public static final String ENV_MIN_APPROVERS = "CYBERARK_MIN_APPROVERS";
        public static final String ENV_PAGE_SIZE = "CYBERARK_REDROCK_PAGE_SIZE";

        public Settings {
            if (rolePattern == null || rolePattern.isBlank()) {
                throw new ConfigException(ENV_PATTERN + " must not be blank");
            }
            if (minApprovers < 1) {
                throw new ConfigException(ENV_MIN_APPROVERS + " must be at least 1");
            }
            if (pageSize < 1 || maxPages < 1) {
                throw new ConfigException(ENV_PAGE_SIZE + " must be at least 1");
            }
        }

        public static Settings defaults() {
            return new Settings(ApproverGroupCheck.DEFAULT_PATTERN, ApproverGroupCheck.DEFAULT_MIN_APPROVERS,
                    ApproverGroupCheck.DEFAULT_PAGE_SIZE, ApproverGroupCheck.DEFAULT_MAX_PAGES);
        }

        public static Settings fromEnvironment(Map<String, String> env) {
            String pattern = env.get(ENV_PATTERN);
            return new Settings(pattern == null || pattern.isBlank() ? ApproverGroupCheck.DEFAULT_PATTERN : pattern.trim(),
                    intOr(env, ENV_MIN_APPROVERS, ApproverGroupCheck.DEFAULT_MIN_APPROVERS),
                    intOr(env, ENV_PAGE_SIZE, ApproverGroupCheck.DEFAULT_PAGE_SIZE),
                    ApproverGroupCheck.DEFAULT_MAX_PAGES);
        }

        private static int intOr(Map<String, String> env, String key, int fallback) {
            String v = env.get(key);
            if (v == null || v.isBlank()) {
                return fallback;
            }
            try {
                return Integer.parseInt(v.trim());
            } catch (NumberFormatException e) {
                throw new ConfigException(key + " must be an integer but was: " + v);
            }
        }
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ApproverGroupRun() {
    }

    public static Map<String, Object> run(CyberArkClient client, DbConfig db, Settings settings) {
        RawRecordRepository roles = new RawRecordRepository(db.schema(), "ispss_role", ROLE_COLUMNS, "ID");
        RawRecordRepository members = new RawRecordRepository(db.schema(), MEMBER_TABLE, ROLE_MEMBER_COLUMNS,
                List.of("role_id", "Guid"));
        RawRecordRepository users = new RawRecordRepository(db.schema(), "ispss_user", USER_COLUMNS, "ID");
        RawRecordRepository results = new RawRecordRepository(db.schema(), RESULT_TABLE, RESULT_COLUMNS, "role_id");

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("command", COMMAND);
        body.put("role_pattern", settings.rolePattern());
        body.put("min_approvers", settings.minApprovers());
        body.put("members_api", client.membersApi().name());

        Connection conn;
        try {
            conn = db.open();
        } catch (SQLException e) {
            fail(body, "DATABASE", null, client.sanitize("could not connect to PostgreSQL: " + e.getMessage()));
            return body;
        }
        try (conn) {
            if (!tryLock(conn)) {
                fail(body, "ALREADY_RUNNING", null, ALREADY_RUNNING);
                return body;
            }
            try {
                return locked(client, conn, db, settings, roles, members, users, results, body);
            } finally {
                unlock(conn);
            }
        } catch (SQLException e) {
            String message = client.sanitize(e.getMessage());
            if (body.containsKey("status")) {
                body.put("database_error", message);
            } else {
                fail(body, "DATABASE", null, message);
            }
            return body;
        }
    }

    /** The run itself, on the one connection that holds the run lock. */
    private static Map<String, Object> locked(CyberArkClient client, Connection conn, DbConfig db, Settings settings,
                                              RawRecordRepository roles, RawRecordRepository members,
                                              RawRecordRepository users, RawRecordRepository results,
                                              Map<String, Object> body) throws SQLException {
        {
            for (RawRecordRepository repo : List.of(roles, members, users, results)) {
                repo.ensureTable(conn);
            }
            addMissingSince(conn, db.schema(), RESULT_TABLE);
            addMissingSince(conn, db.schema(), MEMBER_TABLE);
            ApproverGroupReport report;
            try {
                report = new ApproverGroupCheck(client, settings.rolePattern(), settings.minApprovers(),
                        settings.pageSize(), settings.maxPages()).run();
            } catch (CyberArkApiException e) {
                fail(body, e.kind().name(), e.httpStatus(), client.sanitize(e.getMessage()));
                body.put("visibility_note", ApproverGroupCheck.VISIBILITY_NOTE);
                return body;
            } catch (RuntimeException e) {
                fail(body, "INTERNAL", null, client.sanitize("unexpected error: " + e.getClass().getSimpleName()
                        + (e.getMessage() == null ? "" : ": " + e.getMessage())));
                return body;
            }

            Stored stored = new Stored(client);
            java.util.Set<String> memberStoreFailed = new java.util.HashSet<>();
            int resultStoreFailures = 0;
            for (RoleResult role : report.roles()) {
                stored.put(conn, roles, "ispss_role", role.role().raw());
                role.nestedRoles().forEach(r -> stored.put(conn, roles, "ispss_role", r.raw()));
                for (MemberRows list : role.memberRows()) {
                    for (RoleMember m : list.members()) {
                        ObjectNode row = m.raw().deepCopy();
                        row.put("role_id", list.roleId());
                        if (!stored.put(conn, members, MEMBER_TABLE, row)) {
                            memberStoreFailed.add(list.roleId());
                        }
                    }
                }
                for (CyberArkUser u : role.users()) {
                    stored.put(conn, users, "ispss_user", u.raw());
                }
                if (!stored.put(conn, results, RESULT_TABLE, resultRecord(role, report))) {
                    resultStoreFailures++;
                }
            }

            long checkFailed = report.count(Outcome.CHECK_FAILED);
            String status = !report.search().complete() ? "INCOMPLETE"
                    : checkFailed > 0 || stored.failed > 0 ? "COMPLETED_WITH_FAILURES" : "SUCCESS";
            body.put("status", status);
            Map<String, Object> search = new LinkedHashMap<>();
            search.put("roles_found", report.search().roles().size());
            search.put("pages", report.search().pages());
            search.put("complete", report.search().complete());
            search.put("full_count", report.search().fullCount());
            search.put("notes", report.search().notes().stream().map(client::sanitize).toList());
            body.put("role_search", search);
            body.put("visibility_note", ApproverGroupCheck.VISIBILITY_NOTE);
            Map<String, Object> summary = new LinkedHashMap<>();
            for (Outcome o : Outcome.values()) {
                summary.put(o.name(), report.count(o));
            }
            body.put("summary", summary);
            ArrayNode roleList = MAPPER.createArrayNode();
            report.roles().forEach(r -> roleList.add(roleJson(r)));
            body.put("roles", roleList);
            body.put("stored", stored.counts);
            body.put("reconciliation", reconcile(conn, db.schema(), client, report, resultStoreFailures,
                    memberStoreFailed));
            if (stored.firstError != null) {
                body.put("error", stored.firstError);
            }
            return body;
        }
    }

    /**
     * Marks the stored role results and member rows that this run's qualifying reads did not return (see the class
     * comment for the conditions). All marks are made in one transaction: either every qualifying list and the role
     * search are reconciled, or nothing is.
     */
    private static Map<String, Object> reconcile(Connection conn, String schema, CyberArkClient client,
                                                 ApproverGroupReport report, int resultStoreFailures,
                                                 java.util.Set<String> memberStoreFailed) {
        CyberArkClient.RoleSearch search = report.search();
        Map<String, Object> rolesOut = new LinkedHashMap<>();
        rolesOut.put("performed", false);
        rolesOut.put("marked_missing", 0);
        String roleSkip = !search.complete() ? "the role search could not be shown to be complete"
                : search.fullCount() == null ? "Redrock reported no FullCount for the role search, so its "
                        + "completeness rests on an assumption"
                : search.fullCount() != search.roles().size() ? "FullCount " + search.fullCount() + " but "
                        + search.roles().size() + " role(s) were found"
                : search.duplicates() > 0 ? "the role search returned " + search.duplicates() + " repeated role "
                        + "row(s), so its paging may not be stable"
                : search.roles().isEmpty() ? "the search found no roles; an empty result is not used to mark every "
                        + "stored role missing"
                : resultStoreFailures > 0 ? resultStoreFailures + " role result(s) could not be stored"
                : null;

        // member lists: the lists fetched per role id (a nested role can be listed by more than one approver role)
        Map<String, List<MemberRows>> lists = new LinkedHashMap<>();
        for (RoleResult r : report.roles()) {
            for (MemberRows list : r.memberRows()) {
                lists.computeIfAbsent(list.roleId(), k -> new java.util.ArrayList<>()).add(list);
            }
        }
        Map<String, java.util.Set<String>> qualifying = new LinkedHashMap<>();
        List<Map<String, Object>> skipped = new java.util.ArrayList<>();
        for (Map.Entry<String, List<MemberRows>> e : lists.entrySet()) {
            String why = memberSkip(e.getValue(), memberStoreFailed.contains(e.getKey()));
            if (why != null) {
                Map<String, Object> s = new LinkedHashMap<>();
                s.put("role_id", e.getKey());
                s.put("reason", why);
                skipped.add(s);
                continue;
            }
            java.util.Set<String> guids = new java.util.LinkedHashSet<>();
            e.getValue().forEach(l -> l.members().forEach(m -> guids.add(m.id())));
            qualifying.put(e.getKey(), guids);
        }

        Map<String, Object> membersOut = new LinkedHashMap<>();
        membersOut.put("lists_reconciled", 0);
        membersOut.put("marked_missing", 0);
        membersOut.put("lists_skipped", skipped);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("role_pattern", report.rolePattern());
        out.put("roles", rolesOut);
        out.put("members", membersOut);
        if (roleSkip != null) {
            rolesOut.put("reason", "not reconciled: " + roleSkip);
        }
        if (roleSkip != null && qualifying.isEmpty()) {
            return out;
        }

        String roleSql = "UPDATE " + schema + "." + RESULT_TABLE + " SET \"" + MISSING_SINCE + "\" = now() WHERE "
                + "\"role_pattern\" = ? AND \"" + MISSING_SINCE + "\" IS NULL AND \"role_id\" <> ALL(?)";
        String memberSql = "UPDATE " + schema + "." + MEMBER_TABLE + " SET \"" + MISSING_SINCE + "\" = now() WHERE "
                + "\"role_id\" = ? AND \"" + MISSING_SINCE + "\" IS NULL AND \"Guid\" <> ALL(?)";
        try {
            boolean autoCommit = conn.getAutoCommit();
            conn.setAutoCommit(false);
            try {
                int rolesMarked = 0;
                if (roleSkip == null) {
                    try (java.sql.PreparedStatement ps = conn.prepareStatement(roleSql)) {
                        ps.setString(1, report.rolePattern());
                        ps.setArray(2, conn.createArrayOf("text",
                                search.roles().stream().map(com.keyforge.cyberarkpoc.model.Role::id).toArray()));
                        rolesMarked = ps.executeUpdate();
                    }
                }
                int membersMarked = 0;
                try (java.sql.PreparedStatement ps = conn.prepareStatement(memberSql)) {
                    for (Map.Entry<String, java.util.Set<String>> q : qualifying.entrySet()) {
                        ps.setString(1, q.getKey());
                        ps.setArray(2, conn.createArrayOf("text", q.getValue().toArray()));
                        membersMarked += ps.executeUpdate();
                    }
                }
                conn.commit();
                if (roleSkip == null) {
                    rolesOut.put("performed", true);
                    rolesOut.put("marked_missing", rolesMarked);
                    rolesOut.put("reason", "complete role search: stored results of this pattern whose role was not "
                            + "found now have " + MISSING_SINCE + " (kept with their last outcome; not found does not "
                            + "prove deleted)");
                }
                membersOut.put("lists_reconciled", qualifying.size());
                membersOut.put("marked_missing", membersMarked);
            } catch (SQLException | RuntimeException e) {
                conn.rollback();
                throw e;
            } finally {
                conn.setAutoCommit(autoCommit);
            }
        } catch (SQLException | RuntimeException e) {
            String why = "not reconciled: " + client.sanitize(e.getMessage());
            rolesOut.put("performed", false);
            rolesOut.put("marked_missing", 0);
            rolesOut.put("reason", why);
            membersOut.put("lists_reconciled", 0);
            membersOut.put("marked_missing", 0);
            membersOut.put("error", why);
        }
        return out;
    }

    /** Why one role's fetched member list(s) cannot be reconciled, or {@code null} when they can. */
    private static String memberSkip(List<MemberRows> lists, boolean storeFailed) {
        if (storeFailed) {
            return "not reconciled: a member row of this role could not be stored";
        }
        for (MemberRows list : lists) {
            if (list.softError()) {
                return "not reconciled: the member list flagged IsSoftError";
            }
            if (list.reportedTotal() == null) {
                return "not reconciled: the member list reported no FullCount";
            }
            long distinct = list.members().stream().map(RoleMember::id).distinct().count();
            if (distinct != list.members().size()) {
                return "not reconciled: the member list repeats a member";
            }
            if (list.reportedTotal() != list.members().size()) {
                return "not reconciled: FullCount " + list.reportedTotal() + " but " + list.members().size()
                        + " member(s) listed";
            }
        }
        return null;
    }

    /** Adds the nullable {@code missing_since} column to an existing table of an earlier version; no row changes. */
    private static void addMissingSince(Connection conn, String schema, String table) throws SQLException {
        try (java.sql.PreparedStatement ps = conn.prepareStatement("SELECT 1 FROM information_schema.columns "
                + "WHERE table_schema = ? AND table_name = ? AND column_name = ?")) {
            ps.setString(1, schema);
            ps.setString(2, table);
            ps.setString(3, MISSING_SINCE);
            try (java.sql.ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return;
                }
            }
        }
        try (java.sql.Statement st = conn.createStatement()) {
            st.execute("ALTER TABLE " + schema + "." + table + " ADD COLUMN IF NOT EXISTS \"" + MISSING_SINCE
                    + "\" timestamp with time zone");
        }
    }

    private static boolean tryLock(Connection conn) throws SQLException {
        try (java.sql.PreparedStatement ps = conn.prepareStatement("SELECT pg_try_advisory_lock(?, ?)")) {
            ps.setInt(1, LOCK_SPACE);
            ps.setInt(2, LOCK_KEY);
            try (java.sql.ResultSet rs = ps.executeQuery()) {
                return rs.next() && rs.getBoolean(1);
            }
        }
    }

    /** Releases the lock; closing the connection (or a crash of this process) releases it as well. */
    private static void unlock(Connection conn) {
        try (java.sql.PreparedStatement ps = conn.prepareStatement("SELECT pg_advisory_unlock(?, ?)")) {
            ps.setInt(1, LOCK_SPACE);
            ps.setInt(2, LOCK_KEY);
            ps.executeQuery().close();
        } catch (SQLException ignored) {
            // the connection is closed right after, which releases the lock
        }
    }

    /** The JSON for one role, as returned by REST. */
    static ObjectNode roleJson(RoleResult r) {
        ObjectNode n = MAPPER.createObjectNode();
        n.put("role_id", r.role().id());
        n.put("role_name", r.role().name());
        n.put("role_type", r.role().roleType());
        n.put("outcome", r.outcome().name());
        n.set("reasons", MAPPER.valueToTree(r.reasons()));
        n.put("direct_members", r.directMembers());
        n.set("direct_members_by_type", MAPPER.valueToTree(r.directMembersByType()));
        n.put("active_users", r.activeUsers());
        putBoolean(n, "total_threshold_met", r.totalThresholdMet());
        putBoolean(n, "active_threshold_met", r.activeThresholdMet());
        n.put("getrole_principals", r.details() == null ? null : r.details().principals().size());
        n.set("notes", MAPPER.valueToTree(r.notes()));
        ArrayNode members = n.putArray("members");
        for (MemberResult m : r.members()) {
            ObjectNode mn = members.addObject();
            mn.put("id", m.id());
            mn.put("name", m.name());
            mn.put("type", m.type());
            mn.put("via_role_id", m.viaRoleId());
            mn.put("via_role_name", m.viaRoleName());
            mn.put("outcome", m.outcome().name());
            mn.put("counts_as_active", m.countsAsActive());
            mn.put("detail", m.detail());
        }
        if (r.error() != null) {
            n.put("error", r.error());
        }
        return n;
    }

    private static JsonNode resultRecord(RoleResult r, ApproverGroupReport report) {
        ObjectNode n = MAPPER.createObjectNode();
        ObjectNode role = roleJson(r);
        n.put("role_id", r.role().id());
        n.put("role_name", r.role().name());
        n.put("outcome", r.outcome().name());
        n.put("direct_members", r.directMembers());
        n.set("direct_members_by_type", role.get("direct_members_by_type"));
        n.put("active_users", r.activeUsers());
        n.set("total_threshold_met", role.get("total_threshold_met"));
        n.set("active_threshold_met", role.get("active_threshold_met"));
        n.put("min_approvers", report.minApprovers());
        n.put("role_pattern", report.rolePattern());
        n.set("reasons", role.get("reasons"));
        n.set("notes", role.get("notes"));
        n.set("members", role.get("members"));
        n.put("error", r.error());
        return n;
    }

    private static void putBoolean(ObjectNode n, String field, Boolean value) {
        if (value == null) {
            n.putNull(field);
        } else {
            n.put(field, value);
        }
    }

    private static void fail(Map<String, Object> body, String kind, Integer httpStatus, String error) {
        body.put("status", "FAILED");
        body.put("error_kind", kind);
        body.put("http_status", httpStatus);
        body.put("error", error);
    }

    /** Upserts records one by one; a failed record is counted and the others are still stored. */
    private static final class Stored {
        final CyberArkClient client;
        final Map<String, Map<String, Integer>> counts = new LinkedHashMap<>();
        int failed;
        String firstError;

        Stored(CyberArkClient client) {
            this.client = client;
        }

        /** Stores one record; {@code false} when it could not be stored (counted, and the first error kept). */
        boolean put(Connection conn, RawRecordRepository repo, String table, JsonNode record) {
            Map<String, Integer> c = counts.computeIfAbsent(table, k -> {
                Map<String, Integer> m = new LinkedHashMap<>();
                m.put("inserted", 0);
                m.put("updated", 0);
                m.put("failed", 0);
                return m;
            });
            try {
                JsonNode clean = SecretRedactor.redact(record).value();
                String key = repo.upsert(conn, clean) == RawRecordRepository.Outcome.INSERTED ? "inserted" : "updated";
                c.merge(key, 1, Integer::sum);
                return true;
            } catch (SQLException | RuntimeException e) {
                c.merge("failed", 1, Integer::sum);
                failed++;
                if (firstError == null) {
                    firstError = client.sanitize(table + ": " + e.getMessage());
                }
                return false;
            }
        }
    }
}
