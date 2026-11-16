package com.keyforge.cyberarkpoc.extract;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;

/**
 * What one extraction fetched.
 *
 * @param records       the (redacted) source records that have an id, in API order, without duplicates; empty when
 *                      the records were handed to a sink as they arrived (response-only mode)
 * @param missingId     records skipped because the documented id field was absent
 * @param complete      {@code false} when the data may be incomplete (see {@code notes})
 * @param reportedTotal the total the API reported, if it reports one
 * @param pages         how many pages were requested
 * @param notes         human-readable reasons for {@code complete = false} or other caveats
 * @param recordCount   how many records were fetched (kept in {@code records} or handed to the sink)
 */
public record FetchResult(List<JsonNode> records, int missingId, boolean complete, Integer reportedTotal,
                          int pages, List<String> notes, int recordCount) {

    /** A result whose records are all kept in {@code records}. */
    public FetchResult(List<JsonNode> records, int missingId, boolean complete, Integer reportedTotal, int pages,
                       List<String> notes) {
        this(records, missingId, complete, reportedTotal, pages, notes, records.size());
    }
}
