package com.keyforge.cyberarkpoc.mock;

import static com.keyforge.cyberarkpoc.mock.MockDataset.activeUser;
import static com.keyforge.cyberarkpoc.mock.MockDataset.userWithStatus;

/**
 * The FABRICATED demo dataset used by {@code java -jar cyberark-poc.jar mock} and the Postman
 * collection. Every name, id and value is invented; domains use the reserved {@code example.test}.
 */
public final class SampleData {

    private SampleData() {
    }

    public static MockDataset demo() {
        MockDataset data = new MockDataset();

        // Sufficient: 3 active users.
        data.role("role-fin", "APP-CYA-ISPSS-SCA-AWS-Finance-BUApprovers", "MOCK Finance AWS approvers")
                .userMember("role-fin", activeUser("fin.approver1"))
                .userMember("role-fin", activeUser("fin.approver2"))
                .userMember("role-fin", activeUser("fin.approver3"));

        // Insufficient: 2 active users and one user with no StatusEnum (or Status) value.
        data.role("role-hr", "APP-CYA-ISPSS-SCA-AWS-HR-BUApprovers", "MOCK HR AWS approvers")
                .userMember("role-hr", activeUser("hr.approver1"))
                .userMember("role-hr", activeUser("hr.approver2"))
                .userMember("role-hr", userWithStatus("hr.approver3", null));

        // Insufficient: 3 users but one is disabled.
        data.role("role-pay", "APP-CYA-ISPSS-SCA-AWS-Payments-BUApprovers", "MOCK Payments AWS approvers")
                .userMember("role-pay", activeUser("pay.approver1"))
                .userMember("role-pay", activeUser("pay.approver2"))
                .userMember("role-pay", userWithStatus("pay.approver3", "Suspended"));

        // Insufficient: 2 active users plus a group, which is not expanded or counted.
        data.role("role-mkt", "APP-CYA-ISPSS-SCA-AWS-Marketing-BUApprovers", "MOCK Marketing AWS approvers")
                .userMember("role-mkt", activeUser("mkt.approver1"))
                .userMember("role-mkt", activeUser("mkt.approver2"))
                .member("role-mkt", "group-mkt-leads", "MOCK-Marketing-Leads", "Group");

        // Sufficient: 2 active users plus a nested role with 1 active user and 1 member with no User row.
        data.role("role-ops", "APP-CYA-ISPSS-SCA-AWS-Operations-BUApprovers", "MOCK Operations AWS approvers")
                .userMember("role-ops", activeUser("ops.approver1"))
                .userMember("role-ops", activeUser("ops.approver2"))
                .member("role-ops", "role-ops-leads", "APP-CYA-MOCK-Operations-Leads", "Role");
        data.role("role-ops-leads", "APP-CYA-MOCK-Operations-Leads", "MOCK nested role")
                .userMember("role-ops-leads", activeUser("ops.lead1"))
                .member("role-ops-leads", "user-deleted-001", "deleted.user@example.test", "User");

        // Does not match the AWS pattern, so the check must ignore it.
        data.role("role-azure", "APP-CYA-ISPSS-SCA-AZURE-Finance-BUApprovers", "MOCK Azure approvers")
                .userMember("role-azure", activeUser("az.approver1"));

        // PVWA Safes: 30, so the documented default page size of 25 needs two pages. One carries an extra field
        // to show that unknown, tenant-specific fields are kept.
        for (int i = 1; i <= 30; i++) {
            String name = String.format("MOCK-Safe-%02d", i);
            data.safe(name, name, 100 + i);
        }
        data.withSafeField("mockTenantSpecificField", "kept as-is");

        // PVWA accounts: 120, so the documented default page size of 50 needs three pages. Every account carries a
        // fake secret "MOCK-SECRET-VALUE-<n>"; the first also has a nested Password property.
        for (int i = 1; i <= 120; i++) {
            data.account(String.format("12_%d", i), String.format("MOCK-Safe-%02d", 1 + (i % 30)),
                    "svc_mock_" + i, "MOCK-SECRET-VALUE-" + i);
            if (i == 1) {
                data.withNestedAccountPassword("MOCK-NESTED-PASSWORD-1");
            }
        }

        // PVWA Safe members: every Safe has the same group (memberId 1, so one member in many Safes) and one user;
        // MOCK-Safe-01 has 28 more users, so its 30 members need two pages of the documented default 25.
        for (int i = 1; i <= 30; i++) {
            String name = String.format("MOCK-Safe-%02d", i);
            data.safeMember(name, name, 100 + i, 1, "MOCK Vault Readers", "Group")
                    .safeMember(name, name, 100 + i, 101, "mock_reader_user", "User");
        }
        for (int i = 1; i <= 28; i++) {
            data.safeMember("MOCK-Safe-01", "MOCK-Safe-01", 101, 200 + i, "mock_user_" + i, "User");
        }

        // PVWA target platforms: the official example's WinDesktopLocal, the WinServerLocal used by the mock accounts,
        // and an inactive Unix platform.
        data.targetPlatform(10, "WinDesktopLocal", "Windows Desktop Local Accounts", "Windows", true, 90)
                .targetPlatform(11, "WinServerLocal", "Windows Server Local Accounts", "Windows", true, 30)
                .targetPlatform(25, "UnixSSH", "Unix via SSH", "*NIX", false, 60);

        // PVWA Vault users: the official example's Administrator, one LDAP user (has userDN), one suspended and one
        // disabled user, and 26 more, so a page size of 10 needs three pages.
        data.vaultUser(2, "Administrator", "CyberArk", "Built-InAdmins", true, false, "PVWAMonitor", "Vault Admins")
                .vaultUser(3, "mock.ldap.user", "LDAP", "EPVUser", true, false, "MOCK LDAP Readers")
                .vaultUser(4, "mock.suspended", "CyberArk", "EPVUser", true, true)
                .vaultUser(5, "mock.disabled", "CyberArk", "EPVUser", false, false);
        for (int i = 6; i <= 31; i++) {
            data.vaultUser(i, "mock.user" + i, "CyberArk", "EPVUser", true, false, "MOCK Users");
        }

        // PVWA user groups: Vault groups with members (ids match the mock Vault users), a Directory group (has
        // directory and dn), an empty group, and 26 more, so a page size of 10 needs three pages.
        data.userGroup(11, "Vault Admins", "Vault", "Administrator:2")
                .userGroup(16, "PVWAMonitor", "Vault", "Administrator:2")
                .userGroup(40, "MOCK LDAP Readers", "Directory", "mock.ldap.user:3")
                .userGroup(41, "MOCK Empty Group", "Vault");
        for (int i = 1; i <= 26; i++) {
            data.userGroup(100 + i, "MOCK Users " + i, "Vault", "mock.user" + (5 + i) + ":" + (5 + i));
        }

        // PVWA pending discovered accounts: 128 Windows local accounts (every 10th privileged) plus an AWS access-key
        // account and a Unix account in the official example's other shapes, 130 in all, so the documented default
        // page size of 100 needs two pages. The AWS record uses "discoveryDate", as the official example does.
        for (int i = 1; i <= 128; i++) {
            data.discoveredWindowsAccount("18_" + i, i % 10 == 0 ? "administrator" : "localuser" + i,
                    String.format("mock-win%03d.example.test", i), i % 10 == 0);
        }
        data.discoveredAccountBody("{\"id\": \"18_901\", \"name\": \"mock.example.test-aws_key_user-mock\", "
                        + "\"userName\": \"aws_key_user\", \"address\": \"mock.example.test\", \"discoveryDate\": 1700000800, "
                        + "\"platformType\": \"AWS Access Keys\", \"privileged\": true, \"platformTypeAccountProperties\": "
                        + "{\"awsAccessKeyID\": \"MOCKACCESSKEYID\", \"awsAccountID\": \"123456789012\"}}")
                .discoveredAccountBody("{\"id\": \"18_902\", \"name\": \"mock-unix01-root-mock\", \"userName\": \"root\", "
                        + "\"address\": \"mock-unix01.example.test\", \"discoveryDateTime\": 1700000900, "
                        + "\"platformType\": \"Unix\", \"privileged\": true, \"privilegedCriteria\": \"uid 0\", "
                        + "\"platformTypeAccountProperties\": {\"uid\": 0, \"gid\": 0}}");

        // Policies: 7 across 3 pages, one of each status plus a second Error.
        data.policyPageSize(3)
                .policy("pol-001", "MOCK-Finance-AWS-ReadOnly", "Active", null, null)
                .policy("pol-002", "MOCK-HR-AWS-Admin", "Error", "MOCK_TARGET_UNREACHABLE",
                        "MOCK: the target AWS account could not be reached")
                .policy("pol-003", "MOCK-Payments-AWS-PowerUser", "Warning", "MOCK_PARTIAL_PROVISIONING",
                        "MOCK: the policy was provisioned in 2 of 3 accounts")
                .policy("pol-004", "MOCK-Marketing-AWS-ReadOnly", "Suspended", null, null)
                .policy("pol-005", "MOCK-Legacy-AWS-Admin", "Expired", null, null)
                .policy("pol-006", "MOCK-Ops-AWS-Admin", "Validating", null, null)
                .policy("pol-007", "MOCK-Ops-AWS-Billing", "Error", "MOCK_ROLE_MISSING",
                        "MOCK: the target IAM role no longer exists");
        return data;
    }
}
