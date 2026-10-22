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
 */
public final class ApproverGroupRun {

    public static final String COMMAND = "ispss-approver-groups";

    public static final List<Column> ROLE_COLUMNS = List.of(
            Column.text("ID"), Column.text("Name"), Column.text("RoleType"), Column.bool("ReadOnly"),
            Column.text("Description"));
    public static final List<Column> ROLE_MEMBER_COLUMNS = List.of(
            Column.text("role_id"), Column.text("Guid"), Column.text("Name"), Column.text("Type"),
            Column.bool("IsEffective"), Column.text("OrgPath"), Column.text("OrgId"));
    public static final List<Column> USER_COLUMNS = List.of(
            Column.text("ID"), Column.text("Username"), Column.text("DisplayName"), Column.text("Email"),
            Column.text("LastLogin"), Column.text("Status"), Column.text("StatusEnum"));
    public static final List<Column> RESULT_COLUMNS = List.of(
            Column.text("role_id"), Column.text("role_name"), Column.text("outcome"),
            Column.bigint("direct_members"), Column.jsonb("direct_members_by_type"), Column.bigint("active_users"),
            Column.bool("total_threshold_met"), Column.bool("active_threshold_met"), Column.bigint("min_approvers"),
            Column.text("role_pattern"), Column.jsonb("reasons"), Column.jsonb("notes"), Column.jsonb("members"),
            Column.text("error"));

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
        RawRecordRepository members = new RawRecordRepository(db.schema(), "ispss_role_member", ROLE_MEMBER_COLUMNS,
                List.of("role_id", "Guid"));
        RawRecordRepository users = new RawRecordRepository(db.schema(), "ispss_user", USER_COLUMNS, "ID");
        RawRecordRepository results = new RawRecordRepository(db.schema(), "ispss_approver_group_result",
                RESULT_COLUMNS, "role_id");

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
            for (RawRecordRepository repo : List.of(roles, members, users, results)) {
                repo.ensureTable(conn);
            }
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
            for (RoleResult role : report.roles()) {
                stored.put(conn, roles, "ispss_role", role.role().raw());
                role.nestedRoles().forEach(r -> stored.put(conn, roles, "ispss_role", r.raw()));
                for (MemberRows list : role.memberRows()) {
                    for (RoleMember m : list.members()) {
                        ObjectNode row = m.raw().deepCopy();
                        row.put("role_id", list.roleId());
                        stored.put(conn, members, "ispss_role_member", row);
                    }
                }
                for (CyberArkUser u : role.users()) {
                    stored.put(conn, users, "ispss_user", u.raw());
                }
                stored.put(conn, results, "ispss_approver_group_result", resultRecord(role, report));
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
            if (stored.firstError != null) {
                body.put("error", stored.firstError);
            }
            return body;
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

        void put(Connection conn, RawRecordRepository repo, String table, JsonNode record) {
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
            } catch (SQLException | RuntimeException e) {
                c.merge("failed", 1, Integer::sum);
                failed++;
                if (firstError == null) {
                    firstError = client.sanitize(table + ": " + e.getMessage());
                }
            }
        }
    }
}
