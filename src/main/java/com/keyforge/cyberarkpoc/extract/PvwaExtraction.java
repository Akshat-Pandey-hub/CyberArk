package com.keyforge.cyberarkpoc.extract;

import com.fasterxml.jackson.databind.JsonNode;
import com.keyforge.cyberarkpoc.client.CyberArkApiException;
import com.keyforge.cyberarkpoc.client.PvwaClient;
import com.keyforge.cyberarkpoc.store.Column;

import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * One PVWA extraction: which documented endpoint it reads, its documented response fields (each stored in a column
 * of the same name), the field holding CyberArk's unique id, and the table.
 *
 * @param command     command / route name, e.g. {@code pvwa-safes}
 * @param table       table name, e.g. {@code pvwa_safe}
 * @param idField     the documented id field of each record (unique within one list call)
 * @param keyFields   the fields that together identify a stored record (usually just {@code idField})
 * @param columns     the documented response fields, in documentation order
 * @param description shown in the REST route list
 * @param fetch       reads all records with the given session
 */
public record PvwaExtraction(String command, String table, String idField, List<String> keyFields,
                             List<Column> columns, String description, Function<PvwaClient, FetchResult> fetch) {

    /** An extraction whose records are identified by {@code idField} alone. */
    public PvwaExtraction(String command, String table, String idField, List<Column> columns, String description,
                          Function<PvwaClient, FetchResult> fetch) {
        this(command, table, idField, List.of(idField), columns, description, fetch);
    }

    /**
     * Get all Safes, official page "Get all Safes" (2nd gen):
     * https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/safes%20web%20services%20-%20list%20safes.htm
     * Times are stored as the numbers PVWA returns (creationTime in seconds, lastModificationTime in microseconds
     * in the documented example). {@code accounts} is only returned with includeAccounts=true, which is not sent.
     */
    public static final List<Column> SAFE_COLUMNS = List.of(
            Column.text("safeUrlId"),
            Column.text("safeName"),
            Column.bigint("safeNumber"),
            Column.text("description"),
            Column.text("location"),
            Column.jsonb("creator"),
            Column.jsonb("accounts"),
            Column.bool("olacEnabled"),
            Column.text("managingCPM"),
            Column.bigint("numberOfVersionsRetention"),
            Column.bigint("numberOfDaysRetention"),
            Column.bool("autoPurgeEnabled"),
            Column.bigint("creationTime"),
            Column.bigint("lastModificationTime"),
            Column.bool("isExpiredMember"));

    /**
     * Get accounts, official page "Get accounts":
     * https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/getaccounts.htm
     * The documented {@code secret} field has no column and is removed before anything is returned or stored.
     */
    public static final List<Column> ACCOUNT_COLUMNS = List.of(
            Column.bigint("categoryModificationTime"),
            Column.text("platformId"),
            Column.text("safeName"),
            Column.text("id"),
            Column.text("name"),
            Column.text("address"),
            Column.text("userName"),
            Column.text("secretType"),
            Column.jsonb("platformAccountProperties"),
            Column.jsonb("secretManagement"),
            Column.jsonb("remoteMachinesAccess"),
            Column.bigint("createdTime"),
            Column.bigint("deletionTime"));

    /** Get all Safes: {@code GET /API/Safes/} (offset/limit, documented default limit 25), id {@code safeUrlId}. */
    public static PvwaExtraction safes(ExtractionSettings settings) {
        return new PvwaExtraction("pvwa-safes", "pvwa_safe", "safeUrlId", SAFE_COLUMNS,
                "Safes: GET /API/Safes/ (all pages) -> pvwa_safe",
                client -> OffsetPager.fetchAll(client, "/API/Safes/", Map.of(), settings.pageSizeOr(25),
                        "safeUrlId", settings));
    }

    /**
     * Get accounts: {@code GET /API/Accounts} (offset/limit, documented default limit 50, maximum 1000), id {@code id}.
     * Requires List Accounts in each Safe. The documented result includes a {@code secret} field, which
     * {@link com.keyforge.cyberarkpoc.client.SecretRedactor} removes before anything is returned or stored. The
     * number of accounts PVWA returns is also bounded by its {@code MaxDisplayedRecords} setting; a reported
     * {@code count} that differs from the records received marks the run INCOMPLETE.
     */
    public static PvwaExtraction accounts(ExtractionSettings settings) {
        return new PvwaExtraction("pvwa-accounts", "pvwa_account", "id", ACCOUNT_COLUMNS,
                "Accounts: GET /API/Accounts (all pages, secrets removed) -> pvwa_account",
                client -> OffsetPager.fetchAll(client, "/API/Accounts", Map.of(), settings.pageSizeOr(50), "id",
                        settings));
    }

    /**
     * Get all Safe members, official page "Get all Safe members" (2nd gen):
     * https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/safe%20members%20ws%20-%20list%20safe%20members.htm
     * <ul>
     *   <li>{@code isReadOnly} is in the field table but not in the example; it is kept as documented.</li>
     *   <li>{@code membershipExpirationDate} is typed "Boolean" in the field table, but described as a date and
     *       {@code null} in the example. It is stored as text, so whatever PVWA sends is kept unchanged.</li>
     *   <li>{@code permissions} is a nested object of 22 true/false flags, stored as jsonb.</li>
     * </ul>
     */
    public static final List<Column> SAFE_MEMBER_COLUMNS = List.of(
            Column.text("safeUrlId"),
            Column.text("safeName"),
            Column.bigint("safeNumber"),
            Column.bigint("memberId"),
            Column.text("memberName"),
            Column.text("memberType"),
            Column.text("membershipExpirationDate"),
            Column.bool("isExpiredMembershipEnable"),
            Column.bool("isPredefinedUser"),
            Column.jsonb("permissions"),
            Column.bool("isReadOnly"));

    /**
     * Safe members: for every Safe from {@code GET /API/Safes/}, {@code GET /API/Safes/{SafeUrlId}/Members/}
     * (offset/limit, documented default limit 25). Needs View Safe Members in each Safe. Predefined users are not
     * requested (the documented default); {@code includePredefinedUsers} is not sent.
     *
     * <p>A member is stored per Safe: the key is {@code safeUrlId} + {@code memberId}, because the same user or group
     * can be a member of many Safes. A Safe whose members cannot be read (e.g. HTTP 403) is reported in the notes and
     * makes the run INCOMPLETE; the other Safes are still stored. If every Safe fails, the run fails.
     */
    public static PvwaExtraction safeMembers(ExtractionSettings settings) {
        return new PvwaExtraction("pvwa-safe-members", "pvwa_safe_member", "memberId",
                List.of("safeUrlId", "memberId"), SAFE_MEMBER_COLUMNS,
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
     * Get target platforms, official page "Get target platforms":
     * https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/rest-api-get-target-platforms.htm
     *
     * <p>The page contradicts itself: the JSON example uses PascalCase top-level fields (ID, PlatformID, Name, ...,
     * CredentialsManagementPolicy), while the field table is camelCase and grouped (general.id,
     * credentialsManagement.verification.performPeriodic, ...). The columns follow the example, which is the
     * response body; the community psPAS module formats the target list with the same PascalCase names. If a
     * tenant answers with other names, those fields are listed in {@code fields_without_column} and records without
     * {@code PlatformID} are reported as failed, never silently stored empty.
     */
    public static final List<Column> TARGET_PLATFORM_COLUMNS = List.of(
            Column.bigint("ID"),
            Column.text("PlatformID"),
            Column.text("Name"),
            Column.bool("Active"),
            Column.text("SystemType"),
            Column.text("AllowedSafes"),
            Column.jsonb("PrivilegedAccessWorkflows"),
            Column.jsonb("CredentialsManagementPolicy"),
            Column.jsonb("PrivilegedSessionManagement"));

    /**
     * Target platforms: {@code GET /API/platforms/targets/}, one response with no paging
     * ({@code {"Platforms": [...], "Total": n}}), id {@code PlatformID} (the platform's unique string id, also used
     * by Accounts' {@code platformId}). No filter is sent, so active and inactive platforms are both read. The page
     * states no required permission.
     */
    public static PvwaExtraction targetPlatforms() {
        return new PvwaExtraction("pvwa-target-platforms", "pvwa_target_platform", "PlatformID",
                TARGET_PLATFORM_COLUMNS,
                "Target platforms: GET /API/platforms/targets/ (one response) -> pvwa_target_platform",
                client -> UnpagedList.fetch(client, "/API/platforms/targets/", Map.of(), "Platforms", "Total",
                        "PlatformID"));
    }

    /**
     * Get platform details, official page "Get platform details":
     * https://docs.cyberark.com/pam-self-hosted/latest/en/content/webservices/getplatformdetails.htm
     * <ul>
     *   <li>{@code PlatformID}: String, the platform's unique id.</li>
     *   <li>{@code Properties}: documented as a "List" of key/value pairs from the platform's Policy INI file. Whether
     *       it arrives as a JSON object or an array is not shown (the example is a placeholder), so it is stored as
     *       jsonb exactly as received.</li>
     *   <li>{@code Active}: true/false.</li>
     * </ul>
     */
    public static final List<Column> PLATFORM_DETAIL_COLUMNS = List.of(
            Column.text("PlatformID"),
            Column.jsonb("Properties"),
            Column.bool("Active"));

    /**
     * Platform details: for every platform from Get target platforms, {@code GET /API/Platforms/{PlatformName}/}.
     * The page calls the path value "the unique ID/Name of the platform"; the target list's {@code PlatformID} is used
     * (the community psPAS module calls the same path with the PlatformID). The list is read again in the same run
     * rather than taken from the database, so a stale or empty table can never hide a platform. One call per
     * platform; a platform whose details cannot be read is reported and makes the run INCOMPLETE.
     */
    public static PvwaExtraction platformDetails() {
        return new PvwaExtraction("pvwa-platform-details", "pvwa_platform_detail", "PlatformID",
                PLATFORM_DETAIL_COLUMNS,
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

    /**
     * Get users, official page "Get users":
     * https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/get-users-api.htm
     * <ul>
     *   <li>Lists of strings ({@code authorizedInterfaces}, {@code vaultAuthorization},
     *       {@code allowedAuthenticationMethods}), {@code groupsMembership} and {@code personalDetails} are jsonb.</li>
     *   <li>{@code userDN}, {@code groupsMembership}, {@code enabled}, {@code suspended} and the organization /
     *       department in {@code personalDetails} are returned only with {@code ExtendedDetails}.</li>
     *   <li>The page's group-membership table names the id {@code groupId}; its example uses {@code groupID}. It is
     *       inside {@code groupsMembership} (jsonb), so whichever PVWA sends is kept unchanged.</li>
     * </ul>
     */
    public static final List<Column> USER_COLUMNS = List.of(
            Column.bigint("id"),
            Column.text("username"),
            Column.text("userDN"),
            Column.text("source"),
            Column.text("userType"),
            Column.jsonb("authorizedInterfaces"),
            Column.bool("componentUser"),
            Column.jsonb("vaultAuthorization"),
            Column.jsonb("groupsMembership"),
            Column.jsonb("allowedAuthenticationMethods"),
            Column.text("location"),
            Column.bool("enabled"),
            Column.bool("suspended"),
            Column.jsonb("personalDetails"));

    /** Get users: {@code pageOffset} / {@code pageSize} paging and {@code {"Users": [...], "Total": n}}, no nextLink. */
    public static final OffsetPager.Shape USERS_SHAPE =
            new OffsetPager.Shape("pageOffset", "pageSize", "Users", "Total", null);

    /**
     * Users: {@code GET /API/Users/?ExtendedDetails=true}, paged with {@code pageOffset} / {@code pageSize}, id
     * {@code id}. Needs the Vault authorization <b>Audit users</b>, and returns only users on the caller's level or
     * lower in the Vault hierarchy. The documented {@code pageSize} default is 0 without saying what 0 means, so an
     * explicit page size is always sent (default 1000, the request document's limit); a short page ends the paging and
     * a {@code Total} that differs from the users received marks the run INCOMPLETE.
     */
    public static PvwaExtraction users(ExtractionSettings settings) {
        return new PvwaExtraction("pvwa-users", "pvwa_user", "id", USER_COLUMNS,
                "Users: GET /API/Users/?ExtendedDetails=true (all pages) -> pvwa_user",
                client -> OffsetPager.fetchAll(client, "/API/Users/", Map.of("ExtendedDetails", "true"),
                        settings.pageSizeOr(1000), "id", settings, USERS_SHAPE));
    }

    /**
     * Get groups, official page "Get groups":
     * https://docs.cyberark.com/pam-self-hosted/latest/en/content/webservices/getgroupsfromvault.htm
     * {@code directory} and {@code dn} exist only for Directory groups; {@code members} (a list of
     * {@code {username, id}}) is returned only with {@code includeMembers=true} and is stored as jsonb.
     */
    public static final List<Column> USER_GROUP_COLUMNS = List.of(
            Column.bigint("id"),
            Column.text("groupType"),
            Column.text("directory"),
            Column.text("dn"),
            Column.jsonb("members"),
            Column.text("groupName"),
            Column.text("description"),
            Column.text("location"));

    /**
     * User groups: {@code GET /API/UserGroups/?includeMembers=true}, offset/limit paging and
     * {@code {"value", "count", "nextLink"}}, id {@code id}. Needs <b>Audit users</b>; which groups are returned also
     * depends on the Vault's {@code HideVaultUsersTree} setting (same level or lower, unless it is No). The documented
     * {@code limit} default is 0 without saying what 0 means, so an explicit page size is always sent (default 1000;
     * the page says up to 20,000 groups per request and slower above 1,000).
     */
    public static PvwaExtraction userGroups(ExtractionSettings settings) {
        return new PvwaExtraction("pvwa-user-groups", "pvwa_user_group", "id", USER_GROUP_COLUMNS,
                "User groups: GET /API/UserGroups/?includeMembers=true (all pages) -> pvwa_user_group",
                client -> OffsetPager.fetchAll(client, "/API/UserGroups/", Map.of("includeMembers", "true"),
                        settings.pageSizeOr(1000), "id", settings));
    }

    /**
     * Get discovered accounts, official page "Get discovered accounts":
     * https://docs.cyberark.com/pam-self-hosted/latest/en/content/webservices/get-discovered-accounts.htm
     * <ul>
     *   <li>Only properties that exist for an account are returned; missing ones are stored as NULL.</li>
     *   <li>The field table names the discovery time {@code discoveryDateTime}, while the page's own example records
     *       use {@code discoveryDate}. Both are documented on the page, so both have a column and whichever PVWA
     *       sends is kept; neither is renamed into the other.</li>
     *   <li>Times are Unix time integers, as documented.</li>
     *   <li>{@code additionalProperties} and {@code platformTypeAccountProperties} ("list of name=value pairs", objects
     *       in the example; e.g. sid, uid/gid, SSH key fingerprint, AWS account id) are jsonb.</li>
     * </ul>
     */
    public static final List<Column> DISCOVERED_ACCOUNT_COLUMNS = List.of(
            Column.text("id"),
            Column.text("name"),
            Column.text("userName"),
            Column.text("address"),
            Column.bigint("discoveryDateTime"),
            Column.bigint("discoveryDate"),
            Column.bool("accountEnabled"),
            Column.text("osGroups"),
            Column.text("platformType"),
            Column.text("domain"),
            Column.bigint("lastLogonDateTime"),
            Column.bigint("lastPasswordSetDateTime"),
            Column.bool("passwordNeverExpires"),
            Column.text("osVersion"),
            Column.bool("privileged"),
            Column.text("privilegedCriteria"),
            Column.text("userDisplayName"),
            Column.text("description"),
            Column.bigint("passwordExpirationDateTime"),
            Column.text("osFamily"),
            Column.text("organizationalUnit"),
            Column.jsonb("additionalProperties"),
            Column.jsonb("platformTypeAccountProperties"),
            Column.bigint("numberOfDependencies"));

    /** Always added to the run's notes, so a short or empty result is never read as "no other accounts exist". */
    public static final String DISCOVERY_SCOPE_NOTE = "Discovered accounts are only the accounts still pending "
            + "onboarding, from the machines and domains CyberArk's Accounts Discovery was configured to scan; onboarded "
            + "accounts and anything outside the discovery scope are not listed, so a missing account is not proof "
            + "that it does not exist";

    /**
     * Discovered accounts: {@code GET /API/DiscoveredAccounts/}, offset/limit (documented default 100, maximum 1000;
     * a higher limit is an error) and {@code {"value", "count", "nextLink"}} with {@code count} = the total across all
     * pages; id {@code id}. The caller must belong to <b>Vault Admins or PVWAAccountsFeedAdmins</b>, more than the
     * read-only rights used elsewhere. No filter is sent, so privileged and non-privileged, enabled and disabled
     * accounts are all read.
     */
    public static PvwaExtraction discoveredAccounts(ExtractionSettings settings) {
        return new PvwaExtraction("pvwa-discovered-accounts", "pvwa_discovered_account", "id",
                DISCOVERED_ACCOUNT_COLUMNS,
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
