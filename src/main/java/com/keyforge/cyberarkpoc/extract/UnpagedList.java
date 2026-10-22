package com.keyforge.cyberarkpoc.extract;

import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.client.CyberArkApiException;
import com.keyforge.cyberarkpoc.client.PvwaClient;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Reads a PVWA list endpoint that has no paging and returns everything in one response, e.g. Get target platforms:
 * {@code {"Platforms": [...], "Total": n}}.
 *
 * <p>Like {@link OffsetPager}, the result is never silently complete: a missing array is an invalid response,
 * records without the id field are counted, duplicates are dropped and noted, and a {@code total} that differs from
 * the records received marks the result incomplete.
 */
public final class UnpagedList {

    private UnpagedList() {
    }

    /**
     * @param arrayField the documented field holding the records, e.g. {@code Platforms}
     * @param totalField the documented field holding the total, e.g. {@code Total}
     * @param idField    the documented unique id field of each record, e.g. {@code PlatformID}
     */
    public static FetchResult fetch(PvwaClient client, String path, Map<String, String> query, String arrayField,
                                    String totalField, String idField) {
        JsonNode body = client.get(path, query);
        JsonNode items = body.get(arrayField);
        if (items == null || !items.isArray()) {
            throw new CyberArkApiException(CyberArkApiException.Kind.INVALID_RESPONSE, path, 200,
                    "response has no '" + arrayField + "' array");
        }
        List<JsonNode> records = new ArrayList<>();
        Set<String> ids = new LinkedHashSet<>();
        List<String> notes = new ArrayList<>();
        int missingId = 0;
        int duplicates = 0;
        for (JsonNode item : items) {
            JsonNode id = item.get(idField);
            if (id == null || id.isNull() || id.asText().isBlank()) {
                missingId++;
            } else if (ids.add(id.asText())) {
                records.add(item);
            } else {
                duplicates++;
            }
        }
        boolean complete = true;
        if (duplicates > 0) {
            notes.add(duplicates + " duplicate record(s) were ignored");
        }
        if (missingId > 0) {
            notes.add(missingId + " record(s) had no '" + idField + "' and were not stored");
        }
        Integer total = null;
        JsonNode t = body.get(totalField);
        if (t != null && t.canConvertToInt()) {
            total = t.asInt();
            int seen = records.size() + missingId;
            if (total != seen) {
                complete = false;
                notes.add("the API reported " + totalField + " " + total + " but " + seen + " record(s) were received");
            }
        }
        return new FetchResult(records, missingId, complete, total, 1, notes);
    }
}
