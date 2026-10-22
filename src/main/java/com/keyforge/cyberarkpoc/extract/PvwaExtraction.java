package com.keyforge.cyberarkpoc.extract;

import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.client.CyberArkApiException;
import com.keyforge.cyberarkpoc.client.PvwaClient;

import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * One PVWA extraction: which documented endpoint it reads (path, parameters, paging, loops), the field(s) holding
 * CyberArk's id of a record, and the table. The stored columns are not listed here: they come from the records PVWA
 * actually returns (see {@link com.keyforge.cyberarkpoc.store.GenericRecordStore}), so every field is kept under its
 * exact name. The documentation notes below are only about what each endpoint is documented to return.
 *
 * @param command     command / route name, e.g. {@code pvwa-safes}
 * @param table       table name, e.g. {@code pvwa_safe}
 * @param idField     the documented id field of each record (unique within one list call)
 * @param keyFields   the fields that together identify a stored record (usually just {@code idField})
 * @param description shown in the REST route list
 * @param fetch       reads all records with the given session
 */
public record PvwaExtraction(String command, String table, String idField, List<String> keyFields,
                             String description, Function<PvwaClient, FetchResult> fetch) {

    /** An extraction whose records are identified by {@code idField} alone. */
    public PvwaExtraction(String command, String table, String idField, String description,
                          Function<PvwaClient, FetchResult> fetch) {
        this(command, table, idField, List.of(idField), description, fetch);
    }

    /**
     * Get all Safes: {@code GET /API/Safes/} (offset/limit, documented default limit 25), id {@code safeUrlId}.
     * Official page "Get all Safes" (2nd gen):
     * https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/safes%20web%20services%20-%20list%20safes.htm
     * Documented times are numbers (creationTime in seconds, lastModificationTime in microseconds in the example);
     * {@code accounts} is only returned with includeAccounts=true, which is not sent.
     */
    public static PvwaExtraction safes(ExtractionSettings settings) {
        return new PvwaExtraction("pvwa-safes", "pvwa_safe", "safeUrlId",
                "Safes: GET /API/Safes/ (all pages) -> pvwa_safe",
                client -> OffsetPager.fetchAll(client, "/API/Safes/", Map.of(), settings.pageSizeOr(25),
                        "safeUrlId", settings));
    }

    /**
     * Get accounts: {@code GET /API/Accounts} (offset/limit, documented default limit 50, maximum 1000), id {@code id}.
     * Official page: https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/getaccounts.htm
     * Requires List Accounts in each Safe. The documented result includes a {@code secret} field, which
     * {@link com.keyforge.cyberarkpoc.client.SecretRedactor} removes before anything is returned or stored. The
     * number of accounts PVWA returns is also bounded by its {@code MaxDisplayedRecords} setting; a reported
     * {@code count} that differs from the records received marks the run INCOMPLETE.
     */
    public static PvwaExtraction accounts(ExtractionSettings settings) {
        return new PvwaExtraction("pvwa-accounts", "pvwa_account", "id",
                "Accounts: GET /API/Accounts (all pages, secrets removed) -> pvwa_account",
                client -> OffsetPager.fetchAll(client, "/API/Accounts", Map.of(), settings.pageSizeOr(50), "id",
                        settings));
    }

    /**
     * Safe members: for every Safe from {@code GET /API/Safes/}, {@code GET /API/Safes/{SafeUrlId}/Members/}
     * (offset/limit, documented default limit 25). Official page "Get all Safe members":
     * https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/safe%20members%20ws%20-%20list%20safe%20members.htm
     * Needs View Safe Members in each Safe. Predefined users are not requested (the documented default);
     * {@code includePredefinedUsers} is not sent. ({@code membershipExpirationDate} is typed "Boolean" in the field
     * table but described as a date; it is stored as whatever PVWA sends.)
     *
     * <p>A member is stored per Safe: the key is {@code safeUrlId} + {@code memberId}, because the same user or group
     * can be a member of many Safes. A Safe whose members cannot be read (e.g. HTTP 403) is reported in the notes and
     * makes the run INCOMPLETE; the other Safes are still stored. If every Safe fails, the run fails.
     */
    public static PvwaExtraction safeMembers(ExtractionSettings settings) {
        return new PvwaExtraction("pvwa-safe-members", "pvwa_safe_member", "memberId",
                List.of("safeUrlId", "memberId"),
                "Safe members: GET /API/Safes/{SafeUrlId}/Members/ for every Safe (all pages) -> pvwa_safe_member",
                client -> fetchSafeMembers(client, settings));
    }

    static FetchResult fetchSafeMembers(PvwaClient client, ExtractionSettings settings) {
        FetchResult safes = OffsetPager.fetchAll(client, "/API/Safes/", Map.of(), settings.pageSizeOr(25),
                "safeUrlId", settings);
        return PerItem.each(safes, "safeUrlId", "Safes list", "Safe",
                safeUrlId -> OffsetPager.fetchAll(client, "/API/Safes/" + safeUrlId + "/Members/", Map.of(),
                        settings.pageSizeOr(25), "memberId", settings));
    }

    /**
     * Target platforms: {@code GET /API/platforms/targets/}, one response with no paging
     * ({@code {"Platforms": [...], "Total": n}}), id {@code PlatformID} (the platform's unique string id, also used
     * by Accounts' {@code platformId}). No filter is sent, so active and inactive platforms are both read. The page
     * states no required permission. Official page "Get target platforms":
     * https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/rest-api-get-target-platforms.htm
     *
     * <p>The page contradicts itself: the JSON example uses PascalCase top-level fields (ID, PlatformID, Name, ...),
     * while the field table is camelCase and grouped (general.id, ...). The id field follows the example, as does the
     * community psPAS module; whichever names PVWA really sends are stored as they are. A record without
     * {@code PlatformID} is reported as failed, never stored without its id.
     */
    public static PvwaExtraction targetPlatforms() {
        return new PvwaExtraction("pvwa-target-platforms", "pvwa_target_platform", "PlatformID",
                "Target platforms: GET /API/platforms/targets/ (one response) -> pvwa_target_platform",
                client -> UnpagedList.fetch(client, "/API/platforms/targets/", Map.of(), "Platforms", "Total",
                        "PlatformID"));
    }

    /**
     * Platform details: for every platform from Get target platforms, {@code GET /API/Platforms/{PlatformName}/}.
     * Official page "Get platform details":
     * https://docs.cyberark.com/pam-self-hosted/latest/en/content/webservices/getplatformdetails.htm
     * The page calls the path value "the unique ID/Name of the platform"; the target list's {@code PlatformID} is used
     * (the community psPAS module calls the same path with the PlatformID). {@code Properties} (key/value pairs from
     * the Policy INI file) is documented without saying whether it is an object or an array; it is kept as sent. The
     * list is read again in the same run rather than taken from the database, so a stale or empty table can never hide
     * a platform. One call per platform; a platform whose details cannot be read is reported and makes the run
     * INCOMPLETE.
     */
    public static PvwaExtraction platformDetails() {
        return new PvwaExtraction("pvwa-platform-details", "pvwa_platform_detail", "PlatformID",
                "Platform details: GET /API/Platforms/{PlatformID}/ for every target platform -> pvwa_platform_detail",
                PvwaExtraction::fetchPlatformDetails);
    }

    static FetchResult fetchPlatformDetails(PvwaClient client) {
        FetchResult platforms = UnpagedList.fetch(client, "/API/platforms/targets/", Map.of(), "Platforms", "Total",
                "PlatformID");
        return PerItem.each(platforms, "PlatformID", "Platforms list", "Platform",
                platformId -> single(client.get("/API/Platforms/" + platformId + "/", Map.of()), "PlatformID"));
    }

    /** One object response as a result of one record, or of one record without its id. */
    private static FetchResult single(JsonNode body, String idField) {
        if (body == null || !body.isObject()) {
            throw new CyberArkApiException(CyberArkApiException.Kind.INVALID_RESPONSE, "platform details", 200,
                    "response is not a JSON object");
        }
        JsonNode id = body.get(idField);
        if (id == null || id.isNull() || id.asText().isBlank()) {
            return new FetchResult(List.of(), 1, true, null, 1, List.of("the response had no '" + idField + "'"));
        }
        return new FetchResult(List.of(body), 0, true, null, 1, List.of());
    }

    /** Get users: {@code pageOffset} / {@code pageSize} paging and {@code {"Users": [...], "Total": n}}, no nextLink. */
    public static final OffsetPager.Shape USERS_SHAPE =
            new OffsetPager.Shape("pageOffset", "pageSize", "Users", "Total", null);

    /**
     * Users: {@code GET /API/Users/?ExtendedDetails=true}, paged with {@code pageOffset} / {@code pageSize}, id
     * {@code id}. Official page "Get users": https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/get-users-api.htm
     * Needs the Vault authorization <b>Audit users</b>, and returns only users on the caller's level or lower in the
     * Vault hierarchy. {@code userDN}, {@code groupsMembership}, {@code enabled}, {@code suspended} and the
     * organization / department are returned only with {@code ExtendedDetails}. The documented {@code pageSize}
     * default is 0 without saying what 0 means, so an explicit page size is always sent (default 1000, the request
     * document's limit); a short page ends the paging and a {@code Total} that differs from the users received marks
     * the run INCOMPLETE.
     */
    public static PvwaExtraction users(ExtractionSettings settings) {
        return new PvwaExtraction("pvwa-users", "pvwa_user", "id",
                "Users: GET /API/Users/?ExtendedDetails=true (all pages) -> pvwa_user",
                client -> OffsetPager.fetchAll(client, "/API/Users/", Map.of("ExtendedDetails", "true"),
                        settings.pageSizeOr(1000), "id", settings, USERS_SHAPE));
    }

    /**
     * User groups: {@code GET /API/UserGroups/?includeMembers=true}, offset/limit paging and
     * {@code {"value", "count", "nextLink"}}, id {@code id}. Official page "Get groups":
     * https://docs.cyberark.com/pam-self-hosted/latest/en/content/webservices/getgroupsfromvault.htm
     * Needs <b>Audit users</b>; which groups are returned also depends on the Vault's {@code HideVaultUsersTree}
     * setting. {@code directory} and {@code dn} exist only for Directory groups; {@code members} only with
     * {@code includeMembers=true}. The documented {@code limit} default is 0 without saying what 0 means, so an explicit
     * page size is always sent (default 1000; the page says up to 20,000 groups per request and slower above 1,000).
     */
    public static PvwaExtraction userGroups(ExtractionSettings settings) {
        return new PvwaExtraction("pvwa-user-groups", "pvwa_user_group", "id",
                "User groups: GET /API/UserGroups/?includeMembers=true (all pages) -> pvwa_user_group",
                client -> OffsetPager.fetchAll(client, "/API/UserGroups/", Map.of("includeMembers", "true"),
                        settings.pageSizeOr(1000), "id", settings));
    }

    /** Always added to the run's notes, so a short or empty result is never read as "no other accounts exist". */
    public static final String DISCOVERY_SCOPE_NOTE = "Discovered accounts are only the accounts still pending "
            + "onboarding, from the machines and domains CyberArk's Accounts Discovery was configured to scan; onboarded "
            + "accounts and anything outside the discovery scope are not listed, so a missing account is not proof "
            + "that it does not exist";

    /**
     * Discovered accounts: {@code GET /API/DiscoveredAccounts/}, offset/limit (documented default 100, maximum 1000;
     * a higher limit is an error) and {@code {"value", "count", "nextLink"}} with {@code count} = the total across all
     * pages; id {@code id}. Official page "Get discovered accounts":
     * https://docs.cyberark.com/pam-self-hosted/latest/en/content/webservices/get-discovered-accounts.htm
     * The caller must belong to <b>Vault Admins or PVWAAccountsFeedAdmins</b>, more than the read-only rights used
     * elsewhere. No filter is sent, so privileged and non-privileged, enabled and disabled accounts are all read. Only
     * properties that exist for an account are returned (the field table says {@code discoveryDateTime}, the example
     * {@code discoveryDate}; whichever is sent is stored).
     */
    public static PvwaExtraction discoveredAccounts(ExtractionSettings settings) {
        return new PvwaExtraction("pvwa-discovered-accounts", "pvwa_discovered_account", "id",
                "Discovered accounts (pending only): GET /API/DiscoveredAccounts/ (all pages) -> pvwa_discovered_account",
                client -> {
                    FetchResult r = OffsetPager.fetchAll(client, "/API/DiscoveredAccounts/", Map.of(),
                            settings.pageSizeOr(100), "id", settings);
                    List<String> notes = new java.util.ArrayList<>(r.notes());
                    notes.add(DISCOVERY_SCOPE_NOTE);
                    return new FetchResult(r.records(), r.missingId(), r.complete(), r.reportedTotal(), r.pages(),
                            notes);
                });
    }

    /** Every extraction available so far, in run order. */
    public static List<PvwaExtraction> all(ExtractionSettings settings) {
        return List.of(safes(settings), accounts(settings), safeMembers(settings), targetPlatforms(),
                platformDetails(), users(settings), userGroups(settings), discoveredAccounts(settings));
    }
}
