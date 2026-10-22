package com.keyforge.cyberarkpoc.extract;

import com.keyforge.cyberarkpoc.config.ConfigException;

import java.util.Map;

/**
 * Paging settings shared by the PVWA extractions (request document section 6: "page size of 1000 or less, with
 * throttling between requests").
 *
 * @param pageSize   page size to request; {@code null} means each endpoint's documented default
 * @param throttleMs pause between page requests
 * @param maxPages   safety stop; reaching it marks the run INCOMPLETE
 */
public record ExtractionSettings(Integer pageSize, long throttleMs, int maxPages) {

    public static final String ENV_PAGE_SIZE = "CYBERARK_PVWA_PAGE_SIZE";
    public static final String ENV_THROTTLE_MS = "CYBERARK_PVWA_THROTTLE_MS";
    public static final String ENV_MAX_PAGES = "CYBERARK_PVWA_MAX_PAGES";

    public static final int MAX_PAGE_SIZE = 1000;

    public ExtractionSettings {
        if (pageSize != null && (pageSize < 1 || pageSize > MAX_PAGE_SIZE)) {
            throw new ConfigException(ENV_PAGE_SIZE + " must be between 1 and " + MAX_PAGE_SIZE + " but was: " + pageSize);
        }
        if (throttleMs < 0) {
            throw new ConfigException(ENV_THROTTLE_MS + " must not be negative");
        }
        if (maxPages < 1) {
            throw new ConfigException(ENV_MAX_PAGES + " must be at least 1");
        }
    }

    public static ExtractionSettings defaults() {
        return new ExtractionSettings(null, 100, 100_000);
    }

    public static ExtractionSettings fromEnvironment(Map<String, String> env) {
        return new ExtractionSettings(intOrNull(env, ENV_PAGE_SIZE), longOr(env, ENV_THROTTLE_MS, 100),
                (int) longOr(env, ENV_MAX_PAGES, 100_000));
    }

    /** The configured page size, or the endpoint's documented default. */
    public int pageSizeOr(int documentedDefault) {
        return pageSize == null ? documentedDefault : pageSize;
    }

    private static Integer intOrNull(Map<String, String> env, String key) {
        String v = env.get(key);
        if (v == null || v.isBlank()) {
            return null;
        }
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException e) {
            throw new ConfigException(key + " must be an integer but was: " + v);
        }
    }

    private static long longOr(Map<String, String> env, String key, long fallback) {
        String v = env.get(key);
        if (v == null || v.isBlank()) {
            return fallback;
        }
        try {
            return Long.parseLong(v.trim());
        } catch (NumberFormatException e) {
            throw new ConfigException(key + " must be an integer but was: " + v);
        }
    }
}
