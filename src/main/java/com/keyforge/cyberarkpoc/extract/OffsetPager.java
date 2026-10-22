package com.keyforge.cyberarkpoc.extract;

import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.client.CyberArkApiException;
import com.keyforge.cyberarkpoc.client.PvwaClient;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Pages a PVWA list endpoint that uses the documented {@code offset} / {@code limit} parameters and returns
 * {@code {"value": [...], "count": n, "nextLink": "..."}} (Get all Safes, Get all Safe members, Get accounts,
 * Get groups, Get discovered accounts; see docs/API_CONTRACT_PVWA.md), or the same pattern under other documented
 * names ({@link Shape}, e.g. Get users: {@code pageOffset} / {@code pageSize} and {@code {"Users", "Total"}}).
 *
 * <p>It keeps requesting while a page is full or a {@code nextLink} is present. The result is marked
 * incomplete, never silently complete, when: a page adds no new records (the server ignored the offset), the
 * page limit is reached, or the reported {@code count} differs from the records collected.
 */
public final class OffsetPager {

    /**
     * The documented names of an endpoint's paging parameters and response fields.
     *
     * @param offsetParam   e.g. {@code offset}
     * @param limitParam    e.g. {@code limit}
     * @param arrayField    the field holding the records, e.g. {@code value}
     * @param totalField    the field holding the reported total, e.g. {@code count}
     * @param nextLinkField the field holding the next-page link, or {@code null} if the endpoint has none
     */
    public record Shape(String offsetParam, String limitParam, String arrayField, String totalField,
                        String nextLinkField) {
    }

    /** {@code offset}/{@code limit} and {@code {"value", "count", "nextLink"}}: Safes, Safe members, Accounts, ... */
    public static final Shape VALUE_COUNT = new Shape("offset", "limit", "value", "count", "nextLink");

    private OffsetPager() {
    }

    /**
     * @param path          documented read path, e.g. {@code /API/Safes/}
     * @param extraQuery    documented query parameters to send on every page (besides offset/limit)
     * @param limit         page size
     * @param idField       documented unique id field of each record, e.g. {@code safeUrlId}
     */
    public static FetchResult fetchAll(PvwaClient client, String path, Map<String, String> extraQuery, int limit,
                                       String idField, ExtractionSettings settings) {
        return fetchAll(client, path, extraQuery, limit, idField, settings, VALUE_COUNT);
    }

    /** As above, for an endpoint whose paging parameters and response fields have other documented names. */
    public static FetchResult fetchAll(PvwaClient client, String path, Map<String, String> extraQuery, int limit,
                                       String idField, ExtractionSettings settings, Shape shape) {
        List<JsonNode> records = new ArrayList<>();
        Set<String> ids = new LinkedHashSet<>();
        List<String> notes = new ArrayList<>();
        int missingId = 0;
        int duplicates = 0;
        Integer reportedTotal = null;
        boolean complete = true;
        int offset = 0;
        int pages = 0;

        while (true) {
            if (pages >= settings.maxPages()) {
                complete = false;
                notes.add("stopped at the page limit (" + settings.maxPages() + " pages)");
                break;
            }
            if (pages > 0) {
                pause(settings.throttleMs());
            }
            Map<String, String> query = new LinkedHashMap<>(extraQuery);
            query.put(shape.offsetParam(), String.valueOf(offset));
            query.put(shape.limitParam(), String.valueOf(limit));
            JsonNode page = client.get(path, query);
            pages++;

            JsonNode value = page.get(shape.arrayField());
            if (value == null || !value.isArray()) {
                throw new CyberArkApiException(CyberArkApiException.Kind.INVALID_RESPONSE, path, 200,
                        "response has no '" + shape.arrayField() + "' array");
            }
            JsonNode count = page.get(shape.totalField());
            if (count != null && count.canConvertToInt()) {
                reportedTotal = count.asInt();
            }

            int added = 0;
            for (JsonNode item : value) {
                JsonNode id = item.get(idField);
                if (id == null || id.isNull() || id.asText().isBlank()) {
                    missingId++;
                } else if (ids.add(id.asText())) {
                    records.add(item);
                    added++;
                } else {
                    duplicates++;
                }
            }

            JsonNode nextLink = shape.nextLinkField() == null ? null : page.get(shape.nextLinkField());
            boolean hasNext = nextLink != null && !nextLink.isNull() && !nextLink.asText().isBlank();
            if (value.isEmpty() || (!hasNext && value.size() < limit)) {
                break; // last page
            }
            if (added == 0) {
                complete = false;
                notes.add("paging made no progress at offset " + offset + " (the server returned no new records)");
                break;
            }
            offset += value.size();
        }

        if (duplicates > 0) {
            notes.add(duplicates + " duplicate record(s) across pages were ignored");
        }
        if (missingId > 0) {
            notes.add(missingId + " record(s) had no '" + idField + "' and were not stored");
        }
        int seen = records.size() + missingId;
        if (complete && reportedTotal != null && reportedTotal != seen) {
            complete = false;
            notes.add("the API reported " + shape.totalField() + " " + reportedTotal + " but " + seen
                    + " record(s) were received");
        }
        return new FetchResult(records, missingId, complete, reportedTotal, pages, notes);
    }

    private static void pause(long ms) {
        if (ms <= 0) {
            return;
        }
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new CyberArkApiException(CyberArkApiException.Kind.TRANSPORT, "paging", null, "interrupted", e);
        }
    }
}
