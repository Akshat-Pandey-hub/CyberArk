package com.keyforge.cyberarkpoc.mock;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * FABRICATED data served by {@link MockCyberArkServer}. Nothing here comes from a CyberArk tenant.
 * Build one per test, or use {@link SampleData#demo()}.
 */
public final class MockDataset {

    public record RoleRow(String id, String name, String description) {
    }

    /** {@code type} is sent as-is, so tests can use any casing or an unknown type. */
    public record MemberRow(String guid, String name, String type) {
    }

    /**
     * {@code statusEnum} is sent as {@code StatusEnum}, {@code status} as the localized {@code Status};
     * {@code null} sends JSON null.
     */
    public record UserRow(String id, String username, String displayName, String email, String lastLogin,
                          String status, String statusEnum) {
    }

    public record PolicyRow(String policyId, String name, String status, String statusCode,
                            String statusDescription, String targetCategory, String locationType) {
    }

    final Map<String, RoleRow> roles = new LinkedHashMap<>();
    final Map<String, List<MemberRow>> members = new LinkedHashMap<>();
    final Map<String, UserRow> users = new LinkedHashMap<>();
    final List<PolicyRow> policies = new ArrayList<>();
    int policyPageSize = 50;
    /** PVWA Safes, each a full JSON object in the documented "Get all Safes" shape. */
    final List<ObjectNode> safes = new ArrayList<>();

    private static final ObjectMapper JSON = new ObjectMapper();

    /** Adds a Safe with the fields of the official "Get all Safes" result example (values fabricated). */
    public MockDataset safe(String safeUrlId, String safeName, int safeNumber) {
        ObjectNode s = JSON.createObjectNode();
        s.put("safeUrlId", safeUrlId);
        s.put("safeName", safeName);
        s.put("safeNumber", safeNumber);
        s.put("description", "MOCK safe " + safeName);
        s.put("location", "\\");
        ObjectNode creator = s.putObject("creator");
        creator.put("id", "2");
        creator.put("name", "Administrator");
        s.put("olacEnabled", false);
        s.put("managingCPM", "PasswordManager");
        s.putNull("numberOfVersionsRetention");
        s.put("numberOfDaysRetention", 7);
        s.put("autoPurgeEnabled", false);
        s.put("creationTime", 1_700_000_000L + safeNumber);
        s.put("lastModificationTime", 1_700_000_000_000_000L + safeNumber);
        s.put("isExpiredMember", false);
        safes.add(s);
        return this;
    }

    /** PVWA accounts, each a full JSON object in the documented "Get accounts" shape (including {@code secret}). */
    final List<ObjectNode> accounts = new ArrayList<>();

    /**
     * Adds an account with the fields of the official "Get accounts" result example (values fabricated). The
     * {@code secret} value is a fake marker that tests search for, to prove it never leaves the service.
     */
    public MockDataset account(String id, String safeName, String userName, String secretValue) {
        ObjectNode a = JSON.createObjectNode();
        a.put("categoryModificationTime", 1_700_000_100L);
        a.put("platformId", "WinServerLocal");
        a.put("safeName", safeName);
        a.put("id", id);
        a.put("name", "Operating System-WinServerLocal-" + userName);
        a.put("address", "srv-" + id + ".example.test");
        a.put("userName", userName);
        a.put("secretType", "password");
        a.put("secret", secretValue);
        ObjectNode props = a.putObject("platformAccountProperties");
        props.put("Location", "IT");
        props.put("OwnerName", "MOCK owner");
        ObjectNode management = a.putObject("secretManagement");
        management.put("automaticManagementEnabled", true);
        management.put("status", "success");
        management.put("lastModifiedTime", 1_700_000_200L);
        management.put("lastReconciledTime", 1_700_000_300L);
        management.put("lastVerifiedTime", 1_700_000_400L);
        ObjectNode remote = a.putObject("remoteMachinesAccess");
        remote.put("remoteMachines", "srv-a.example.test;srv-b.example.test");
        remote.put("accessRestrictedToRemoteMachines", false);
        a.put("createdTime", 1_700_000_000L);
        accounts.add(a);
        return this;
    }

    /** PVWA Safe members per {@code safeUrlId}, each in the documented "Get all Safe members" shape. */
    final Map<String, List<ObjectNode>> safeMembers = new LinkedHashMap<>();

    /**
     * Adds a member to a Safe with the fields of the official "Get all Safe members" result example (values
     * fabricated). The permission flags follow the documented list; only list/view rights are true.
     */
    public MockDataset safeMember(String safeUrlId, String safeName, int safeNumber, long memberId, String memberName,
                                  String memberType) {
        ObjectNode m = JSON.createObjectNode();
        m.put("safeUrlId", safeUrlId);
        m.put("safeName", safeName);
        m.put("safeNumber", safeNumber);
        m.put("memberId", memberId);
        m.put("memberName", memberName);
        m.put("memberType", memberType);
        m.putNull("membershipExpirationDate");
        m.put("isExpiredMembershipEnable", false);
        m.put("isPredefinedUser", false);
        ObjectNode p = m.putObject("permissions");
        for (String flag : List.of("useAccounts", "retrieveAccounts", "listAccounts", "addAccounts",
                "updateAccountContent", "updateAccountProperties", "initiateCPMAccountManagementOperations",
                "specifyNextAccountContent", "renameAccounts", "deleteAccounts", "unlockAccounts", "manageSafe",
                "manageSafeMembers", "backupSafe", "viewAuditLog", "viewSafeMembers", "accessWithoutConfirmation",
                "createFolders", "deleteFolders", "moveAccountsAndFolders", "requestsAuthorizationLevel1",
                "requestsAuthorizationLevel2")) {
            p.put(flag, flag.equals("listAccounts") || flag.equals("viewSafeMembers"));
        }
        m.put("isReadOnly", true);
        safeMembers.computeIfAbsent(safeUrlId, k -> new ArrayList<>()).add(m);
        return this;
    }

    /** PVWA target platforms, each in the documented "Get target platforms" example shape (PascalCase). */
    final List<ObjectNode> targetPlatforms = new ArrayList<>();

    /** Adds a target platform with the fields of the official "Get target platforms" example (values fabricated). */
    public MockDataset targetPlatform(long id, String platformId, String name, String systemType, boolean active,
                                      int changeEveryXDays) {
        ObjectNode p = JSON.createObjectNode();
        p.put("ID", id);
        p.put("PlatformID", platformId);
        p.put("Name", name);
        p.put("Active", active);
        p.put("SystemType", systemType);
        p.put("AllowedSafes", ".*");
        ObjectNode workflows = p.putObject("PrivilegedAccessWorkflows");
        for (String rule : List.of("RequireDualControlPasswordAccessApproval", "EnforceCheckinCheckoutExclusiveAccess",
                "EnforceOnetimePasswordAccess", "RequireUsersToSpecifyReasonForAccess")) {
            ObjectNode r = workflows.putObject(rule);
            r.put("IsActive", rule.equals("RequireUsersToSpecifyReasonForAccess"));
            r.put("IsAnException", false);
        }
        ObjectNode policy = p.putObject("CredentialsManagementPolicy");
        ObjectNode verification = policy.putObject("Verification");
        verification.put("PerformAutomatic", false);
        verification.put("RequirePasswordEveryXDays", 7);
        verification.put("AutoOnAdd", false);
        verification.put("IsRequirePasswordEveryXDaysAnException", false);
        verification.put("AllowManual", true);
        ObjectNode change = policy.putObject("Change");
        change.put("PerformAutomatic", true);
        change.put("RequirePasswordEveryXDays", changeEveryXDays);
        change.put("AutoOnAdd", false);
        change.put("IsRequirePasswordEveryXDaysAnException", false);
        change.put("AllowManual", true);
        ObjectNode reconcile = policy.putObject("Reconcile");
        reconcile.put("AutomaticReconcileWhenUnsynced", false);
        reconcile.put("AllowManual", true);
        policy.putObject("SecretUpdateConfiguration").put("ChangePasswordInResetMode", false);
        p.putObject("PrivilegedSessionManagement").put("PSMServerId", "");
        targetPlatforms.add(p);

        // Get platform details: PlatformID, Properties (key/value pairs from the Policy INI file), Active.
        ObjectNode details = JSON.createObjectNode();
        details.put("PlatformID", platformId);
        ObjectNode properties = details.putObject("Properties");
        properties.put("PolicyID", platformId);
        properties.put("PolicyName", name);
        properties.put("PolicyType", "regular");
        properties.put("ImmediateInterval", "5");
        properties.put("Interval", "1440");
        properties.put("MinValidityPeriod", "60");
        properties.put("PerformPeriodicChange", "Yes");
        properties.put("RequirePasswordChangeEveryXDays", String.valueOf(changeEveryXDays));
        details.put("Active", active);
        platformDetails.put(platformId, details);
        return this;
    }

    /**
     * PVWA Vault users in the documented "Get users" shape. Each entry holds the always-returned fields under
     * {@code base} and the {@code ExtendedDetails}-only fields under {@code extended}.
     */
    final List<ObjectNode> vaultUsers = new ArrayList<>();

    /** Adds a Vault user with the fields of the official "Get users" example (values fabricated). */
    public MockDataset vaultUser(long id, String username, String source, String userType, boolean enabled,
                                 boolean suspended, String... groups) {
        ObjectNode base = JSON.createObjectNode();
        base.put("id", id);
        base.put("username", username);
        base.put("source", source);
        base.put("userType", userType);
        base.putArray("authorizedInterfaces").add("PVWA").add("PSM");
        base.put("componentUser", false);
        base.putArray("vaultAuthorization").add("AuditUsers");
        base.putArray("allowedAuthenticationMethods");
        base.put("location", "\\");
        ObjectNode personal = base.putObject("personalDetails");
        personal.put("firstName", "Mock");
        personal.put("middleName", "");
        personal.put("lastName", username);
        ObjectNode extended = JSON.createObjectNode();
        if (source.equals("LDAP")) {
            extended.put("userDN", "CN=" + username + ",OU=Mock,DC=example,DC=test");
        }
        ArrayNode membership = extended.putArray("groupsMembership");
        for (int i = 0; i < groups.length; i++) {
            ObjectNode g = membership.addObject();
            g.put("groupID", 100 + i);
            g.put("groupName", groups[i]);
            g.put("groupType", "Vault");
        }
        extended.put("enabled", enabled);
        extended.put("suspended", suspended);
        extended.put("organization", "MOCK Org");
        extended.put("department", "MOCK Dept");
        ObjectNode entry = JSON.createObjectNode();
        entry.set("base", base);
        entry.set("extended", extended);
        vaultUsers.add(entry);
        return this;
    }

    /** Test-only: sets a top-level field of the last Vault user. */
    public MockDataset withVaultUserField(String name, String value) {
        ((ObjectNode) vaultUsers.get(vaultUsers.size() - 1).get("base")).put(name, value);
        return this;
    }

    /** PVWA user groups in the documented "Get groups" shape, members included (the mock removes them if not asked). */
    final List<ObjectNode> userGroups = new ArrayList<>();

    /**
     * Adds a user group with the fields of the official "Get groups" result (values fabricated). {@code directory}
     * and {@code dn} are set only for Directory groups, as documented. Members are {@code "username:id"} pairs.
     */
    public MockDataset userGroup(long id, String groupName, String groupType, String... members) {
        ObjectNode g = JSON.createObjectNode();
        g.put("id", id);
        g.put("groupType", groupType);
        if (groupType.equals("Directory")) {
            g.put("directory", "mock.example.test");
            g.put("dn", "CN=" + groupName + ",OU=Groups,DC=mock,DC=example,DC=test");
        }
        ArrayNode list = g.putArray("members");
        for (String m : members) {
            String[] parts = m.split(":");
            list.addObject().put("username", parts[0]).put("id", Long.parseLong(parts[1]));
        }
        g.put("groupName", groupName);
        g.put("description", "MOCK group " + groupName);
        g.put("location", "\\");
        userGroups.add(g);
        return this;
    }

    /** Test-only: sets a top-level field of the last user group. */
    public MockDataset withUserGroupField(String name, String value) {
        userGroups.get(userGroups.size() - 1).put(name, value);
        return this;
    }

    /** PVWA pending discovered accounts in the documented "Get discovered accounts" shape. */
    final List<ObjectNode> discoveredAccounts = new ArrayList<>();

    /**
     * Adds a pending discovered Windows local account with the fields of the official example's first record (values
     * fabricated); only populated properties are included, as documented.
     */
    public MockDataset discoveredWindowsAccount(String id, String userName, String address, boolean privileged) {
        ObjectNode a = JSON.createObjectNode();
        a.put("id", id);
        a.put("name", address + "-" + userName + "-mock");
        a.put("userName", userName);
        a.put("address", address);
        a.put("discoveryDateTime", 1_700_000_500L);
        a.put("accountEnabled", true);
        a.put("osGroups", privileged ? "Administrators" : "Users");
        a.put("platformType", "Windows Server Local");
        a.put("domain", "mock.example.test");
        a.put("lastLogonDateTime", 1_700_000_600L);
        a.put("lastPasswordSetDateTime", 1_700_000_700L);
        a.put("passwordNeverExpires", false);
        a.put("osVersion", "Windows Server 2019 Standard");
        a.put("privileged", privileged);
        if (privileged) {
            a.put("privilegedCriteria", "Administrators");
        }
        a.put("userDisplayName", "MOCK " + userName);
        a.put("description", "MOCK discovered account");
        a.put("osFamily", "Server");
        a.put("organizationalUnit", "CN=Users,DC=mock,DC=example,DC=test");
        a.putObject("platformTypeAccountProperties").put("SID", "S-1-5-21-0-0-0-" + id.replace("_", ""));
        ObjectNode additional = a.putObject("additionalProperties");
        additional.put("AccountType", "Local");
        additional.put("CreationMethod", "WebService");
        a.put("numberOfDependencies", privileged ? 2 : 0);
        discoveredAccounts.add(a);
        return this;
    }

    /** Adds a pending discovered account from a raw JSON object (e.g. an AWS or Unix shape). */
    public MockDataset discoveredAccountBody(String json) {
        try {
            discoveredAccounts.add((ObjectNode) JSON.readTree(json));
        } catch (java.io.IOException e) {
            throw new IllegalArgumentException(e);
        }
        return this;
    }

    /** PVWA platform details per PlatformID, in the documented "Get platform details" shape. */
    final Map<String, ObjectNode> platformDetails = new LinkedHashMap<>();

    /** Test-only: replaces the details of a platform with a raw JSON body. */
    public MockDataset platformDetailsBody(String platformId, String json) {
        try {
            platformDetails.put(platformId, (ObjectNode) JSON.readTree(json));
        } catch (java.io.IOException e) {
            throw new IllegalArgumentException(e);
        }
        return this;
    }

    /** Test-only: adds a field to the last target platform. */
    public MockDataset withTargetPlatformField(String name, String value) {
        targetPlatforms.get(targetPlatforms.size() - 1).put(name, value);
        return this;
    }

    /** Test-only: adds a field to the last member of a Safe. */
    public MockDataset withSafeMemberField(String safeUrlId, String name, String value) {
        List<ObjectNode> list = safeMembers.get(safeUrlId);
        list.get(list.size() - 1).put(name, value);
        return this;
    }

    /** Test-only: adds a nested {@code Password} property to the last account, to prove redaction is recursive. */
    public MockDataset withNestedAccountPassword(String value) {
        ((ObjectNode) accounts.get(accounts.size() - 1).get("platformAccountProperties")).put("Password", value);
        return this;
    }

    /** Removes a field from the last added Safe, e.g. to simulate a record without its id. */
    public MockDataset withoutSafeField(String name) {
        safes.get(safes.size() - 1).remove(name);
        return this;
    }

    /** Adds a field to the last added Safe, e.g. to simulate a tenant-specific property. */
    public MockDataset withSafeField(String name, String value) {
        safes.get(safes.size() - 1).put(name, value);
        return this;
    }

    public MockDataset role(String id, String name, String description) {
        roles.put(id, new RoleRow(id, name, description));
        members.putIfAbsent(id, new ArrayList<>());
        return this;
    }

    public MockDataset member(String roleId, String guid, String name, String type) {
        members.computeIfAbsent(roleId, k -> new ArrayList<>()).add(new MemberRow(guid, name, type));
        return this;
    }

    /** Adds a user row and makes it a member of the role. */
    public MockDataset userMember(String roleId, UserRow user) {
        user(user);
        return member(roleId, user.id(), user.username(), "User");
    }

    public MockDataset user(UserRow user) {
        users.put(user.id(), user);
        return this;
    }

    public MockDataset policy(String policyId, String name, String status, String statusCode, String statusDescription) {
        policies.add(new PolicyRow(policyId, name, status, statusCode, statusDescription, "Cloud console", "AWS"));
        return this;
    }

    public MockDataset policyPageSize(int size) {
        if (size < 1) {
            throw new IllegalArgumentException("page size must be at least 1");
        }
        policyPageSize = size;
        return this;
    }

    /** A fabricated active user {@code <id>@example.test}. */
    public static UserRow activeUser(String id) {
        return userWithStatus(id, "Active");
    }

    /** A fabricated user whose StatusEnum and display Status are both {@code statusEnum}. */
    public static UserRow userWithStatus(String id, String statusEnum) {
        return userWithStatuses(id, statusEnum, statusEnum);
    }

    /** A fabricated user with separate StatusEnum and localized Status values. */
    public static UserRow userWithStatuses(String id, String statusEnum, String status) {
        return new UserRow(id, id + "@example.test", "Mock " + id, id + "@example.test",
                "/Date(1760000000000)/", status, statusEnum);
    }
}
