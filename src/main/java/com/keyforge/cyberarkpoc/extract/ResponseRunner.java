package com.keyforge.cyberarkpoc.extract;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyforge.cyberarkpoc.client.CyberArkApiException;
import com.keyforge.cyberarkpoc.client.PvwaClient;
import com.keyforge.cyberarkpoc.client.ResponseBody;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Response-only mode: runs one extraction with the same session, paging and completeness checks as the database mode
 * ({@link ExtractionRunner}) and returns the records as JSON. It never connects to PostgreSQL.
 *
 * <p>The records are written into a {@link ResponseBody} as each page arrives (in memory up to 1 MB, then a temporary
 * file), so memory does not grow with the number of records. The caller sends the result and then releases it
 * ({@link ResponseBody#release}); the REST server and the command line both do.
 *
 * <p>Status as in the database mode: SUCCESS; INCOMPLETE when completeness could not be proven (the records received
 * are returned, with the reason in {@code notes}); COMPLETED_WITH_FAILURES when records had no id; FAILED when the
 * CyberArk call or the local temporary file failed. A failed run returns no records, so partial data is never
 * returned as if it were the whole list.
 */
public final class ResponseRunner {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ResponseRunner() {
    }

    public static Map<String, Object> run(PvwaExtraction extraction, PvwaClient client, ResponseBody.Settings spool) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("command", extraction.command());
        body.put("mode", "response");

        try (ResponseBody.Writer writer = new ResponseBody.Writer(spool)) {
            JsonGenerator out = MAPPER.getFactory().createGenerator(writer)
                    .disable(JsonGenerator.Feature.AUTO_CLOSE_TARGET);
            out.writeStartArray();
            FetchResult fetched;
            try {
                fetched = extraction.fetch().apply(client, record -> write(out, record));
            } catch (CyberArkApiException e) {
                fail(body, e.kind().name(), e.httpStatus(), client.sanitize(e.getMessage()));
                return body;
            } catch (UncheckedIOException e) {
                return localFailure(body, e.getCause(), client);
            } catch (RuntimeException e) {
                fail(body, "INTERNAL", null, client.sanitize("unexpected error: " + ExtractionRunner.describe(e)));
                return body;
            }
            out.writeEndArray();
            out.close();
            ResponseBody records = writer.finish();

            String status = !fetched.complete() ? "INCOMPLETE"
                    : fetched.missingId() > 0 ? "COMPLETED_WITH_FAILURES" : "SUCCESS";
            body.put("status", status);
            body.put("records_returned", fetched.recordCount());
            body.put("failed", fetched.missingId());
            body.put("pages", fetched.pages());
            body.put("reported_total", fetched.reportedTotal());
            body.put("complete", fetched.complete());
            body.put("notes", fetched.notes().stream().map(client::sanitize).toList());
            body.put("records", records);
            return body;
        } catch (IOException e) {
            return localFailure(body, e, client);
        }
    }

    private static void write(JsonGenerator out, JsonNode record) {
        try {
            MAPPER.writeTree(out, record);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** The temporary file of this service failed (disk full, local limit): not a CyberArk or network failure. */
    private static Map<String, Object> localFailure(Map<String, Object> body, IOException e, PvwaClient client) {
        body.remove("status");
        fail(body, e instanceof ResponseBody.LocalLimitException ? "LOCAL_LIMIT" : "LOCAL_STORAGE", null,
                client.sanitize(e.getMessage()));
        return body;
    }

    private static void fail(Map<String, Object> body, String kind, Integer httpStatus, String error) {
        body.put("status", "FAILED");
        body.put("error_kind", kind);
        body.put("http_status", httpStatus);
        body.put("error", error);
    }
}
