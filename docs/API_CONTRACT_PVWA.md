# CyberArk PVWA: API contract for every endpoint in the KeyForge request document

Source document: `D:\CyberArk PVWA Read-Only API Access Request – KeyForge.docx` (Oct 22, 2026).
Read on 2026-10-22 from the official PAM Self-Hosted ("latest") documentation at docs.cyberark.com.

Labels:
- **OFFICIAL**: read on the official page (URL given)
- **COMMUNITY**: the psPAS PowerShell module (github.com/pspete/psPAS @ 11f490a, 2026-10-18), not official
- **NOT STATED**: the official page does not say

All URLs are relative to `https://<PVWA_Server_address>/PasswordVault`. Every call sends the header
`Authorization: <session token>` (the docs say "the token that identifies the session").

---

## 1. Logon: document `POST /API/Auth/<CyberArk|LDAP|RADIUS>/Logon` ✅
OFFICIAL: https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/cyberark%20authentication%20-%20logon_v10.htm
- `POST /API/auth/{Cyberark|Windows|LDAP|RADIUS}/Logon/`, JSON body `{"username", "password"}` (optional `newPassword`, `concurrentSession` up to 300 sessions).
- Result: the **session token** (a JSON string). **Default session length: 20 minutes.**
- 1st gen (old): `/WebServices/auth/Cyberark/CyberArkAuthenticationService.svc/Logon`.

## 2. Logoff: document `POST /API/Auth/Logoff` ✅
OFFICIAL: …/sdk/cyberark%20authentication%20-%20logoff_v10.htm
- `POST /API/Auth/Logoff/` with the session token. Result `{}`.

## 3. Health check: document `GET /API/Server/Verify` ❌ wrong path
OFFICIAL: https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/server%20web%20services%20-%20verify.htm
- `GET /WebServices/PIMServices.svc/Verify/`
- Result: `{"ServerName", "ServerID", "ApplicationName": "PasswordVault", "AuthenticationMethods": [...]}`
- The official page lists the `Authorization` header as **mandatory**. The document's section 8 says the test "needs no credentials", which is not what the docs state. (psPAS also calls `GET /API/verify/` on newer versions: COMMUNITY.)
- ⚠️ Not to be confused with `POST /API/Accounts/{id}/Verify/`, a **CPM password-verification action, not a read**. Never call it.

## 4. Accounts: document `GET /API/Accounts` (paged) ✅
OFFICIAL: https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/getaccounts.htm
- Permission: **List Accounts** in the Safe.
- `GET /API/Accounts?offset=&limit=&search=&searchType=&sort=&filter=&savedfilter=`
  - `limit` default 50, **max 1000**; `offset` default 0
  - `filter`: `safeName eq X`, `modificationTime gte <t>`
  - saved filters: Regular, Recently, New, Link, Deleted, PolicyFailures, AccessedByUsers, ModifiedByUsers, ModifiedByCPM, DisabledPasswordByUser, DisabledPasswordByCPM, ScheduledForChange, ScheduledForVerify, ScheduledForReconcile, SuccessfullyReconciled, FailedChange, FailedVerify, FailedReconcile, LockedOrNew, Locked, Favorites
- **Number of accounts returned is determined by the PVWA `MaxDisplayedRecords` setting.**
- Result: `{"value": [ … ], "count": n, "nextLink": "…"}`. Each account:
  - `id`, `name`, `address`, `userName`, `platformId`, `safeName`, `secretType` (password/key)
  - `platformAccountProperties{…}`: free key-value pairs, varies by platform
  - `secretManagement{automaticManagementEnabled, manualManagementReason, status (inProcess/Success/Failure), lastModifiedTime, lastReconciledTime, lastVerifiedTime}`
  - `remoteMachinesAccess{remoteMachines, accessRestrictedToRemoteMachines}`
  - `categoryModificationTime`, `createdTime`, `deletionTime` (only if deleted but not purged)
- ⚠️ The documented result **also lists a `secret` field**. The extractor must **drop `secret`** (and anything matching it) before returning or storing. The document promises we never retrieve secrets.

## 5. Safes: document `GET /API/Safes` ✅
OFFICIAL: https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/safes%20web%20services%20-%20list%20safes.htm
- Returns **only Safes the caller is a member of**; internal Safes are not returned.
- `GET /API/Safes/?offset=&limit=&search=&sort=&includeAccounts=&extendedDetails=`: `limit` default **25**; `extendedDetails` default true.
- Result: `{"value": [ … ], "count": n, "nextLink": "api/safes?offset=25&limit=25&useCache=False"}`. Each Safe: `safeUrlId, safeName, safeNumber, description, location, creator{id,name}, olacEnabled, managingCPM, numberOfVersionsRetention, numberOfDaysRetention, autoPurgeEnabled, creationTime, lastModificationTime, isExpiredMember`.

## 6. Safe members: document `GET /API/Safes/{safe}/Members` ✅
OFFICIAL: https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/safe%20members%20ws%20-%20list%20safe%20members.htm
- Permission: **View Safe Members** in the Safe.
- `GET /API/Safes/{SafeUrlId}/Members/?offset=&limit=&filter=&search=&sort=`: `limit` default 25
  - `filter`: `memberType eq user|group`, `membershipExpired eq true|false`, `includePredefinedUsers eq true` (default: **predefined users excluded**)
- Result: `{"value": [ … ], "count": n}`. Each member:
  - `safeUrlId, safeName, safeNumber, memberId, memberName, memberType (user/group), membershipExpirationDate, isExpiredMembershipEnable, isPredefinedUser, isReadOnly`
  - `permissions{…}`: 22 true/false flags: useAccounts, retrieveAccounts, listAccounts, addAccounts, updateAccountContent, updateAccountProperties, initiateCPMAccountManagementOperations, specifyNextAccountContent, renameAccounts, deleteAccounts, unlockAccounts, manageSafe, manageSafeMembers, backupSafe, viewAuditLog, viewSafeMembers, accessWithoutConfirmation, createFolders, deleteFolders, moveAccountsAndFolders, requestsAuthorizationLevel1, requestsAuthorizationLevel2
- Note: the `viewAuditLog` permission is described as "View account and user activity in the Safe" (relevant to §11).

## 7. Target platforms: document `GET /API/Platforms/Targets` ✅
OFFICIAL: https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/rest-api-get-target-platforms.htm
- `GET /API/platforms/targets/?Filter=&search=`. Filters: active, systemType, periodicVerify, manualVerify, periodicChange, manualChange, automaticReconcile, manualReconcile. **No paging.**
- Result: `{"Platforms": [ … ], "Total": n}`. Each platform:
  - `ID, PlatformID, Name, Active, SystemType, AllowedSafes`
  - `PrivilegedAccessWorkflows{RequireDualControlPasswordAccessApproval, EnforceCheckinCheckoutExclusiveAccess, EnforceOnetimePasswordAccess, RequireUsersToSpecifyReasonForAccess: {IsActive, IsAnException}}`
  - `CredentialsManagementPolicy{Verification, Change: {PerformAutomatic, RequirePasswordEveryXDays, AutoOnAdd, IsRequirePasswordEveryXDaysAnException, AllowManual}, Reconcile{AutomaticReconcileWhenUnsynced, AllowManual}, SecretUpdateConfiguration{ChangePasswordInResetMode}}`
  - `PrivilegedSessionManagement{PSMServerId}`
- The example uses PascalCase while the field table uses camelCase, so the parser must ignore letter case.
- Permission: NOT STATED.

## 8. Platform details: document `GET /API/Platforms/{id}` ✅ (path detail)
OFFICIAL: https://docs.cyberark.com/pam-self-hosted/latest/en/content/webservices/getplatformdetails.htm
- `GET /API/Platforms/{PlatformName}/`. Result `{"PlatformID", "Properties": <every key/value from the platform's policy INI>, "Active"}`.
- Permission: NOT STATED.

## 9. Users: document `GET /API/Users` ✅ (permission issue)
OFFICIAL: https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/get-users-api.htm
- Permission: **Audit users** (vault authorization). Returns users **at the same level or lower in the Vault hierarchy**. About 6000 users in about 20 s.
- `GET /API/Users/?filter=&sort=&search=&ExtendedDetails=&pageOffset=&pageSize=`
  - filters: userType, componentUser, userName
  - **`ExtendedDetails=true` needed** for `enabled`, `suspended`, `groupsMembership`, `userDN`, organization, department
- Result: `{"Users": [ … ], "Total": n}`. Each user: `id, username, source (CyberArk/LDAP), userType, componentUser, authorizedInterfaces[], vaultAuthorization[], groupsMembership[{groupID, groupName, groupType}], allowedAuthenticationMethods[], location, enabled, suspended, personalDetails{firstName, middleName, lastName, organization, department}, userDN`.

## 10. Groups: document `GET /API/UserGroups` ✅ (permission issue)
OFFICIAL: https://docs.cyberark.com/pam-self-hosted/latest/en/content/webservices/getgroupsfromvault.htm
- Permission: **Audit users**. Visibility depends on the `HideVaultUsersTree` setting in dbparm.ini. Up to 20,000 groups per request.
- `GET /API/UserGroups/?filter=&sort=&search=&includeMembers=&offset=&limit=`
  - filters: `groupType eq Directory|Vault`, `groupName eq X`
  - **`includeMembers=true`** returns members
- Result: `{"value": [ … ], "count": n, "nextLink": "…"}`. Each group: `id, groupType, directory, dn, groupName, description, location, members[{username, id}]`.

## 11. Account activity: document "Account activities (optional)" ⚠️
OFFICIAL: https://docs.cyberark.com/pam-self-hosted/latest/en/content/sdk/files%20-%20get%20file%20activity%20by%20id.htm
- Officially documented **only as 1st gen**: `GET /WebServices/PIMServices.svc/Accounts/{AccountID}/Activities/`. **One call per account.**
- Result: activity records with `AccountName, Path, ActivityCode, Activity, Time, UserName, ClientID, Reason, MoreInfo`.
- Permission: NOT STATED (the Safe permission `viewAuditLog` = "View account and user activity in the Safe" is the likely one).
- COMMUNITY: psPAS also uses `GET /API/Accounts/{id}/Activities` on newer versions.

## 12. Discovered accounts: document `GET /API/DiscoveredAccounts` ✅ (permission issue)
OFFICIAL: https://docs.cyberark.com/pam-self-hosted/latest/en/content/webservices/get-discovered-accounts.htm
- Permission: caller **must belong to the Vault Admins or PVWAAccountsFeedAdmins group**. Returns only **pending** (not yet onboarded) discovered accounts.
- `GET /API/DiscoveredAccounts/?filter=&search=&searchType=&offset=&limit=`
  - filters: platformType, privileged, accountEnabled
  - `limit` default 100, **max 1000** (too high → error)
- Result: `{"value": [ … ], "count": <total across all pages>, "nextLink": "…"}`. Only populated properties are returned. Fields:
  - `id, name, userName, address, discoveryDateTime, accountEnabled, osGroups, platformType, domain, lastLogonDateTime, lastPasswordSetDateTime, passwordNeverExpires, osVersion, privileged, privilegedCriteria, userDisplayName, description, passwordExpirationDateTime, osFamily, organizationalUnit, numberOfDependencies`
  - `additionalProperties{…}` and `platformTypeAccountProperties{…}` (sid, uid/gid, SSH fingerprint, AWS account id / access key id, Azure tenant id)

---

## 13. Corrections the request document needs

| # | Document says | Official docs say |
|---|---|---|
| C1 | "Vault-level Audit users authorization only if the activity/audit data… is in scope" | **Audit users is required for `GET /API/Users` and `GET /API/UserGroups`**, which are core items in section 5 |
| C2 | Only "List accounts" and "View safe members" are needed | **Discovered accounts needs membership of Vault Admins or PVWAAccountsFeedAdmins**, far broader than list/view. Either drop discovered accounts or ask for the narrower PVWAAccountsFeedAdmins group explicitly |
| C3 | Health check `GET /API/Server/Verify`; connectivity test "needs no credentials" | Official: `GET /WebServices/PIMServices.svc/Verify/`, with Authorization listed as mandatory. The section 8 `curl` should use that path and treat a 401 as "network OK, auth needed" |
| C4 | Activity: "Account activities" | Officially 1st-gen `…/PIMServices.svc/Accounts/{id}/Activities/`, one call per account; the permission is not stated (likely Safe `viewAuditLog`) |
| C5 | Paging "page size of 1000 or less" | Defaults differ per endpoint (Accounts 50/max 1000, Safes 25, Members 25, Discovered 100/max 1000, Users pageSize, Groups offset/limit, Platforms none). Accounts are also capped by `MaxDisplayedRecords` |
| C6 | — | Users require `ExtendedDetails=true` and groups `includeMembers=true` to return the full data |
| C7 | — | The accounts result schema includes a `secret` field; state in the document that the extractor discards it |

## 14. Calls that must never be made (blocked in code)
- `POST /API/Accounts/{id}/Password/Retrieve` (retrieve secret)
- Any account action: `POST /API/Accounts/{id}/Verify`, `/Change`, `/Reconcile`, `/CheckIn`, `/Unlock`, connect/PSM calls
- Any POST/PUT/PATCH/DELETE except Logon and Logoff
