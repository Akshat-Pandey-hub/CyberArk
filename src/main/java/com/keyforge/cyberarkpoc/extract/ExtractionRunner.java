package com.keyforge.cyberarkpoc.extract;

import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.client.CyberArkApiException;
import com.keyforge.cyberarkpoc.client.PvwaClient;
import com.keyforge.cyberarkpoc.store.DbConfig;
import com.keyforge.cyberarkpoc.store.GenericRecordStore;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Runs one extraction end to end: open the database, create the table if absent, fetch every page, make the table
 * hold every field of the records received ({@link GenericRecordStore#prepare}), and store each record under its
 * exact field names (insert, or update the row with the same CyberArk id).
 *
 * <p>Status: SUCCESS; INCOMPLETE when the fetch could not prove completeness; COMPLETED_WITH_FAILURES when records
 * failed to store or had no id; FAILED when the CyberArk call, the database or the code itself failed. The database
 * is opened before CyberArk is called, so a database problem never costs a logon. Every message that leaves this
 * method is passed through {@link PvwaClient#sanitize}.
 */
public final class ExtractionRunner {

    private ExtractionRunner() {
    }

    public static Map<String, Object> run(PvwaExtraction extraction, PvwaClient client, DbConfig db) {
        GenericRecordStore store = new GenericRecordStore(db.schema(), extraction.table(), extraction.keyFields());

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("command", extraction.command());
        body.put("table", store.table());

        Connection conn;
        try {
            conn = db.open();
        } catch (SQLException e) {
            fail(body, "DATABASE", null, client.sanitize("could not connect to PostgreSQL: " + e.getMessage()));
            return body;
        }

        try (conn) {
            store.ensureTable(conn);
            FetchResult fetched;
            try {
                fetched = extraction.fetch().apply(client);
            } catch (CyberArkApiException e) {
                fail(body, e.kind().name(), e.httpStatus(), client.sanitize(e.getMessage()));
                return body;
            } catch (RuntimeException e) {
                fail(body, "INTERNAL", null, client.sanitize("unexpected error: " + describe(e)));
                return body;
            }
            GenericRecordStore.Prepared prepared = store.prepare(conn, fetched.records());
            Stored stored = store(store, prepared, conn, fetched, extraction, client);

            String status = !fetched.complete() ? "INCOMPLETE"
                    : stored.failed > 0 || fetched.missingId() > 0 ? "COMPLETED_WITH_FAILURES" : "SUCCESS";
            body.put("status", status);
            body.put("extracted", fetched.records().size());
            body.put("inserted", stored.inserted);
            body.put("updated", stored.updated);
            body.put("failed", stored.failed + fetched.missingId());
            body.put("pages", fetched.pages());
            body.put("reported_total", fetched.reportedTotal());
            body.put("complete", fetched.complete());
            body.put("notes", fetched.notes().stream().map(client::sanitize).toList());
            body.put("schema_changes", prepared.changes());
            if (stored.firstError != null) {
                body.put("error", stored.firstError);
            }
            body.put("records", fetched.records());
            return body;
        } catch (SQLException e) {
            String message = client.sanitize(e.getMessage());
            if (body.containsKey("status")) {
                body.put("database_error", message); // keep the outcome already decided (e.g. a close error)
            } else {
                fail(body, "DATABASE", null, message);
            }
            return body;
        }
    }

    private record Stored(int inserted, int updated, int failed, String firstError) {
    }

    private static Stored store(GenericRecordStore store, GenericRecordStore.Prepared prepared, Connection conn,
                                FetchResult fetched, PvwaExtraction extraction, PvwaClient client) {
        int inserted = 0;
        int updated = 0;
        int failed = 0;
        String firstError = null;
        for (JsonNode record : fetched.records()) {
            String id = String.join("/", extraction.keyFields().stream()
                    .map(k -> record.path(k).asText()).toList());
            try {
                if (store.upsert(conn, prepared, record) == GenericRecordStore.Outcome.INSERTED) {
                    inserted++;
                } else {
                    updated++;
                }
            } catch (SQLException | RuntimeException e) {
                failed++;
                if (firstError == null) {
                    firstError = client.sanitize("record " + id + ": " + e.getMessage());
                }
            }
        }
        return new Stored(inserted, updated, failed, firstError);
    }

    private static void fail(Map<String, Object> body, String kind, Integer httpStatus, String error) {
        body.put("status", "FAILED");
        body.put("error_kind", kind);
        body.put("http_status", httpStatus);
        body.put("error", error);
    }

    static String describe(Throwable e) {
        return e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage());
    }
}
