package com.keyforge.cyberarkpoc.extract;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;

/**
 * What one extraction fetched.
 *
 * @param records       the (redacted) source records that have an id, in API order, without duplicates
 * @param missingId     records skipped because the documented id field was absent
 * @param complete      {@code false} when the data may be incomplete (see {@code notes})
 * @param reportedTotal the total the API reported, if it reports one
 * @param pages         how many pages were requested
 * @param notes         human-readable reasons for {@code complete = false} or other caveats
 */
public record FetchResult(List<JsonNode> records, int missingId, boolean complete, Integer reportedTotal,
                          int pages, List<String> notes) {
}
