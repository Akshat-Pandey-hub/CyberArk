package com.keyforge.cyberarkpoc.extract;

import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.client.CyberArkApiException;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Runs one documented call per item of a parent list (e.g. the members of every Safe, the details of every
 * platform) and combines the results.
 *
 * <ul>
 *   <li>An item whose id cannot be put into a URL path as-is is reported in the notes and not called.</li>
 *   <li>An item whose call fails (e.g. HTTP 403 or 404) is reported in the notes; the other items are still read and
 *       the result is incomplete.</li>
 *   <li>If every item fails, the first failure is thrown: a failed run, not an incomplete one.</li>
 * </ul>
 */
final class PerItem {

    /**
     * An id that can be used in a URL path as-is. The docs say "+ & %" and spaces are not supported in URL values;
     * "/", "?" and "#" would change the path, and "." / ".." are path navigation.
     */
    static final Pattern URL_SAFE_ID = Pattern.compile("[^/?#%+&\\s\"<>\\\\^`{|}]+");

    private PerItem() {
    }

    /**
     * @param parents   the parent list, already fetched
     * @param idField   the parent field used in the child URL, e.g. {@code safeUrlId}
     * @param listLabel how the parent list is named in notes, e.g. {@code Safes list}
     * @param itemLabel how one parent is named in notes, e.g. {@code Safe}
     * @param child     reads the child records of one parent id
     */
    static FetchResult each(FetchResult parents, String idField, String listLabel, String itemLabel,
                            Function<String, FetchResult> child) {
        List<JsonNode> records = new ArrayList<>();
        List<String> notes = new ArrayList<>();
        parents.notes().forEach(n -> notes.add(listLabel + ": " + n));
        boolean complete = parents.complete();
        int missingId = 0;
        int pages = parents.pages();
        int failed = 0;
        CyberArkApiException firstFailure = null;
        for (JsonNode parent : parents.records()) {
            String id = parent.get(idField).asText();
            if (!URL_SAFE_ID.matcher(id).matches() || id.equals(".") || id.equals("..")) {
                complete = false;
                failed++;
                notes.add(itemLabel + " " + id + ": its " + idField + " cannot be used in a URL path, not read");
                continue;
            }
            try {
                FetchResult result = child.apply(id);
                records.addAll(result.records());
                missingId += result.missingId();
                pages += result.pages();
                if (!result.complete()) {
                    complete = false;
                }
                result.notes().forEach(n -> notes.add(itemLabel + " " + id + ": " + n));
            } catch (CyberArkApiException e) {
                complete = false;
                failed++;
                if (firstFailure == null) {
                    firstFailure = e;
                }
                notes.add(itemLabel + " " + id + ": not read: " + e.getMessage());
            }
        }
        if (firstFailure != null && failed == parents.records().size()) {
            throw firstFailure; // nothing could be read
        }
        return new FetchResult(records, missingId, complete, null, pages, notes);
    }
}
