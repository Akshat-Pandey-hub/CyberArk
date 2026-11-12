package com.keyforge.cyberarkpoc.check;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.keyforge.cyberarkpoc.check.PolicyHealthCheck.Outcome;
import com.keyforge.cyberarkpoc.check.PolicyHealthCheck.PolicyResult;
import com.keyforge.cyberarkpoc.client.CyberArkApiException;
import com.keyforge.cyberarkpoc.client.PolicyClient;
import com.keyforge.cyberarkpoc.store.Column;
import com.keyforge.cyberarkpoc.store.DbConfig;
import com.keyforge.cyberarkpoc.store.GenericRecordStore;
import com.keyforge.cyberarkpoc.store.RawRecordRepository;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Runs Use Case 2 end to end: read every policy ({@link PolicyClient}), give each an outcome
 * ({@link PolicyHealthCheck}), store both, and answer with one JSON summary (REST route {@code ispss/policy-health},
 * CLI {@code ispss-policy-health}).
 *
 * <p>Tables:
 * <ul>
 *   <li>{@code uap_policy}: every policy as returned, one column per top-level field under its exact name
 *       ({@link GenericRecordStore}; nested objects such as {@code metadata} are jsonb), plus our {@code policy_id}
 *       (the key: UAP {@code metadata.policyId}, SCA {@code policyId}) and {@code policy_api}</li>
 *   <li>{@code uap_policy_health_result}: the latest outcome per policy, key {@code policy_id} (our columns)</li>
 * </ul>
 *
 * <p>{@code status} describes the retrieval: FAILED (nothing is stored, nothing is concluded), INCOMPLETE (stored,
 * but the list may be partial), COMPLETED_WITH_FAILURES (a policy could not be stored), SUCCESS. {@code health}
 * is the conclusion: FINDINGS, ALL_HEALTHY (only after a complete retrieval with every policy verified) or
 * UNDETERMINED. A failed or incomplete retrieval is never reported as ALL_HEALTHY.
 */
public final class PolicyHealthRun {

    public static final String COMMAND = "ispss-policy-health";
    public static final String POLICY_TABLE = "uap_policy";
    public static final String RESULT_TABLE = "uap_policy_health_result";
    public static final String KEY = "policy_id";

    public static final List<Column> RESULT_COLUMNS = List.of(
            Column.text("policy_id"), Column.text("policy_api"), Column.text("policy_name"), Column.text("outcome"),
            Column.text("status"), Column.text("status_code"), Column.text("status_description"),
            Column.text("target_category"), Column.text("location_type"), Column.text("reason"),
            Column.bool("retrieval_complete"));

    public static final String FAILED_NOTE =
            "the policy list could not be read, so nothing can be said about the health of the policies";
    public static final String INCOMPLETE_NOTE =
            "the policy list may be incomplete: policies that were not received are neither healthy nor unhealthy";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private PolicyHealthRun() {
    }

    public static Map<String, Object> run(PolicyClient client, DbConfig db) {
        String api = client.api().name().toLowerCase(Locale.ROOT);
        GenericRecordStore policies = new GenericRecordStore(db.schema(), POLICY_TABLE, List.of(KEY));
        RawRecordRepository results = new RawRecordRepository(db.schema(), RESULT_TABLE, RESULT_COLUMNS, KEY);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("command", COMMAND);
        body.put("policy_api", api);

        Connection conn;
        try {
            conn = db.open();
        } catch (SQLException e) {
            fail(body, "DATABASE", null, client.sanitize("could not connect to PostgreSQL: " + e.getMessage()));
            return body;
        }
        try (conn) {
            policies.ensureTable(conn);
            results.ensureTable(conn);
            PolicyClient.Listing listing;
            try {
                listing = client.listPolicies();
            } catch (CyberArkApiException e) {
                fail(body, e.kind().name(), e.httpStatus(), client.sanitize(e.getMessage()));
                return body;
            } catch (RuntimeException e) {
                fail(body, "INTERNAL", null, client.sanitize("unexpected error: " + e.getClass().getSimpleName()
                        + (e.getMessage() == null ? "" : ": " + e.getMessage())));
                return body;
            }

            List<String> notes = new ArrayList<>(listing.notes());
            boolean complete = listing.complete();
            // Evaluate every policy; keep the last copy of an id that appears twice (and say so).
            Map<String, PolicyResult> byId = new LinkedHashMap<>();
            Map<String, JsonNode> recordById = new LinkedHashMap<>();
            List<PolicyResult> withoutId = new ArrayList<>();
            for (JsonNode policy : listing.policies()) {
                PolicyResult r = PolicyHealthCheck.evaluate(client.api(), policy);
                if (r.policyId() == null || r.policyId().isBlank()) {
                    withoutId.add(r);
                    continue;
                }
                if (byId.put(r.policyId(), r) != null) {
                    complete = false;
                    notes.add("policy " + r.policyId() + " was returned more than once; the paging may be unreliable");
                }
                ObjectNode record = policy.deepCopy();
                record.put(KEY, r.policyId());
                record.put("policy_api", api);
                recordById.put(r.policyId(), record);
            }
            if (!withoutId.isEmpty()) {
                notes.add(withoutId.size() + " policies have no policy id and could not be stored");
            }

            List<JsonNode> records = new ArrayList<>(recordById.values());
            GenericRecordStore.Prepared prepared = policies.prepare(conn, records);
            Map<String, Map<String, Integer>> stored = new LinkedHashMap<>();
            int failed = 0;
            String firstError = null;
            for (JsonNode record : records) {
                String id = record.get(KEY).asText();
                try {
                    count(stored, POLICY_TABLE, policies.upsert(conn, prepared, record).name());
                } catch (SQLException | RuntimeException e) {
                    count(stored, POLICY_TABLE, "FAILED");
                    failed++;
                    firstError = firstError != null ? firstError : client.sanitize(POLICY_TABLE + " " + id + ": "
                            + e.getMessage());
                }
                try {
                    count(stored, RESULT_TABLE, results.upsert(conn, resultRecord(byId.get(id), api, complete)).name());
                } catch (SQLException | RuntimeException e) {
                    count(stored, RESULT_TABLE, "FAILED");
                    failed++;
                    firstError = firstError != null ? firstError : client.sanitize(RESULT_TABLE + " " + id + ": "
                            + e.getMessage());
                }
            }

            List<PolicyResult> all = new ArrayList<>(byId.values());
            all.addAll(withoutId);
            Map<String, Long> summary = new LinkedHashMap<>();
            for (Outcome o : Outcome.values()) {
                summary.put(o.name(), all.stream().filter(r -> r.outcome() == o).count());
            }
            String health = summary.get(Outcome.FINDING.name()) > 0 ? "FINDINGS"
                    : complete && summary.get(Outcome.CANNOT_VERIFY.name()) == 0 ? "ALL_HEALTHY" : "UNDETERMINED";
            String status = !complete ? "INCOMPLETE"
                    : failed > 0 || !withoutId.isEmpty() ? "COMPLETED_WITH_FAILURES" : "SUCCESS";

            body.put("status", status);
            body.put("health", health);
            if (!complete) {
                body.put("health_note", INCOMPLETE_NOTE);
            }
            Map<String, Object> retrieval = new LinkedHashMap<>();
            retrieval.put("pages", listing.pages());
            retrieval.put("received", listing.policies().size());
            retrieval.put("reported_total", listing.reportedTotal());
            retrieval.put("complete", complete);
            retrieval.put("notes", notes.stream().map(client::sanitize).toList());
            body.put("retrieval", retrieval);
            body.put("summary", summary);
            body.put("findings", all.stream().filter(r -> r.outcome() == Outcome.FINDING).map(PolicyHealthRun::json)
                    .toList());
            body.put("policies", all.stream().map(PolicyHealthRun::json).toList());
            body.put("stored", stored);
            body.put("schema_changes", prepared.changes());
            if (firstError != null) {
                body.put("error", firstError);
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

    /** One policy result as returned by REST. */
    static ObjectNode json(PolicyResult r) {
        ObjectNode n = MAPPER.createObjectNode();
        n.put("policy_id", r.policyId());
        n.put("policy_name", r.name());
        n.put("outcome", r.outcome().name());
        n.put("status", r.status());
        n.put("status_code", r.statusCode());
        n.put("status_description", r.statusDescription());
        n.put("target_category", r.targetCategory());
        n.put("location_type", r.locationType());
        n.put("reason", r.reason());
        return n;
    }

    private static JsonNode resultRecord(PolicyResult r, String api, boolean complete) {
        ObjectNode n = json(r);
        n.put("policy_api", api);
        n.put("retrieval_complete", complete);
        return n;
    }

    private static void count(Map<String, Map<String, Integer>> stored, String table, String outcome) {
        Map<String, Integer> c = stored.computeIfAbsent(table, k -> {
            Map<String, Integer> m = new LinkedHashMap<>();
            m.put("inserted", 0);
            m.put("updated", 0);
            m.put("failed", 0);
            return m;
        });
        c.merge(outcome.toLowerCase(Locale.ROOT), 1, Integer::sum);
    }

    private static void fail(Map<String, Object> body, String kind, Integer httpStatus, String error) {
        body.put("status", "FAILED");
        body.put("health", "UNDETERMINED");
        body.put("health_note", FAILED_NOTE);
        body.put("error_kind", kind);
        body.put("http_status", httpStatus);
        body.put("error", error);
    }
}
