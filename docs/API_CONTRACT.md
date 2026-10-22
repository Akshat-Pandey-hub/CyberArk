# CyberArk (Idira) Identity API contract: Use Case 1 (approver group validation)

Re-verified on **2026-10-23** for Use Case 1: every role whose name matches
`APP-CYA-ISPSS-SCA-AWS-%-BUApprovers` needs at least 3 valid approvers.
**Nothing here was observed on a real CyberArk tenant.** A mock or a fixture is never treated as proof.

## Status labels

| Label | Meaning |
|---|---|
| **VERIFIED** | Stated on an official CyberArk page (URL given), read on 2026-10-23 |
| **VERIFIED (SDK)** | Not on a documentation page, but in CyberArk's official SDK source (`github.com/cyberark/ark-sdk-python` @ `db8353f`, 2025-11-16; `ark-sdk-golang` @ `c267d29`). Working official code, but not a published contract |
| **ASSUMED** | Our assumption; must be confirmed on a tenant or by the client |
| **MISMATCHED** | Two official sources disagree, or our code or a fixture disagrees with an official source |
| **UNRESOLVED** | No official source establishes it |

## Official sources

| Id | Page |
|---|---|
| S1 | Create an API token: https://api-docs.cyberark.com/create-api-token/docs/create-api-token |
| S2 | Use queries (Redrock): https://docs.cyberark.com/developer/latest/en/developer/use-queries/ |
| S3 | Data dictionary, Role: https://docs.cyberark.com/developer/latest/en/developer/data-dictionary/role/ |
| S4 | Data dictionary, User: https://docs.cyberark.com/developer/latest/en/developer/data-dictionary/user/ |
| S5 | Roles API reference: https://api-docs.cyberark.com/identity-docs-api/docs/roles-api. The page lists two servers: CyberArk's public SwaggerHub mock `https://virtserver.swaggerhub.com/CyberArk/roles-api/main`, which serves the reference's example responses, and `https://{tenant_url}/` (default `example.id.cyberark.cloud`). On 2026-10-23 the operation list did not render and the OpenAPI file is not publicly downloadable, so operation details come from the example responses the mock serves plus the 2026-10-21 reading recorded below |
| SDK | `ark_sdk_python/services/identity/roles/ark_identity_roles_service.py`, `.../identity/common/ark_identity_base_service.py`, `.../common/isp/ark_isp_service_client.py` |

---

## 1. Host (the `uap` vs `id` discrepancy)

| Item | Finding | Status |
|---|---|---|
| Identity APIs (Redrock, Roles) on `https://<tenant>.id.cyberark.cloud/` (no `/api`) | S5 declares the Roles API server `https://{tenant_url}/` with default `example.id.cyberark.cloud`. S2 says the base URL is "your Idira Identity tenant". S1's token endpoint is `https://<identity-tenant-id>.id.cyberark.cloud/oauth2/platformtoken` | **VERIFIED** (S1, S2, S5) |
| `https://<subdomain>.uap.cyberark.cloud/api` | S1's table of service API URLs lists this host **only for "Access Control Policies"**. It lists no Identity, Redrock or Roles URL on any `/api` service host | **VERIFIED** (S1): `uap` is the policies host |
| Identity APIs on the `uap` host (`https://8a11f5d4-….uap.cyberark.cloud/api/Redrock/query` and `/api/Roles/GetRole`, from the client mail) | Not stated on any official page | **UNRESOLVED**: client confirmation required |
| Identity APIs through a platform proxy | The official SDK sends Identity calls by default to `https://<subdomain>.cyberark.cloud/api/idadmin/<path>` (the platform host with prefix `api/idadmin/`), and falls back to the `id.cyberark.cloud` host with no prefix | **VERIFIED (SDK)**. Shows Identity APIs can sit behind a non-`id` host, but does not prove the `uap` form in the mail |
| Header `X-IDAP-NATIVE-CLIENT: true` | Sent by the SDK on Identity calls; not mentioned on S2–S5; **not sent by our `CyberArkClient`** | **VERIFIED (SDK)**; whether it is required is **UNRESOLVED** |

**Consequence:** the host must stay configurable (it already is: `CYBERARK_IDENTITY_BASE_URL`). The documented default is `https://<tenant>.id.cyberark.cloud`. The client must confirm whether their mail's `uap…/api` form works. Not a blocker for building.

## 2. Authentication (platform token)

| Item | Finding | Status |
|---|---|---|
| Endpoint | `POST https://<identity-tenant-id>.id.cyberark.cloud/oauth2/platformtoken` | **VERIFIED** (S1) |
| Body | URL-encoded form: `grant_type=client_credentials`, `client_id` = the service user's login name, `client_secret` = its password | **VERIFIED** (S1) |
| Response | `{"access_token": "eyJh...", "token_type": "Bearer", "expires_in": 900}` (200) | **VERIFIED** (S1, example) |
| Use | `Authorization: Bearer <access_token>` | **VERIFIED** (S1; S5 "Bearer Auth", JWT) |
| Service user | "Is OAuth confidential client" (sets "Is Service User" and "Password never expires"), added to the role the API needs | **VERIFIED** (S1) |
| Platform token accepted by Redrock / Roles | S1 says the platform token authenticates "the service APIs listed above", and Identity is not in that list. S2 instead configures a separate OAuth2 web app for Redrock (scope `reporting`, REST regex `Redrock/query`, token URL `<tenant>/oauth2/token/identityapi`, client credentials as a Basic auth header, a role with the **Report Management** right). The SDK uses the platform token (its "isp" authenticator) for Identity roles and Redrock calls | **MISMATCHED** (S1 vs S2), resolved in favour of the platform token only by the **SDK**. Client confirmation recommended |
| Token error format / HTTP status | Not shown on S1 | **UNRESOLVED** |
| Custom OAuth2 token (`/oauth2/token/{app_id}`) | S1: needed for SCA APIs and for cloud-console / group-assignment **policies** (Use Case 2), not for Identity APIs | **VERIFIED** (S1). Not needed for Use Case 1 |

## 3. Redrock query

| Item | Finding | Status |
|---|---|---|
| Endpoint | `POST /Redrock/query` (read-only: "does not let you modify or create data") | **VERIFIED** (S2) |
| Body | `{"Script": "<SQL>", "args": {...}}`; `args` optional. The text says "Args", the example uses `args`; the SDK's directory search uses `Args` | **VERIFIED** (S2), letter case **MISMATCHED** (S2 text vs example) |
| Paging arguments | `PageNumber`, `PageSize`, `Limit`, `Caching` (-1 = live data), `Direction` (example writes `direction`), `SortBy`. "Specifying these parameters requires you to invoke the endpoint multiple times" | **VERIFIED** (S2) |
| Paging semantics | Whether `PageNumber` starts at 0 or 1, the server's default page size when no `args` is sent, and how `Limit` interacts with `PageSize` are not stated (the example uses PageNumber 10000, PageSize 10000, Limit 1000). The SDK's directory search defaults to PageNumber 1, PageSize 100000, Limit 100000 | **UNRESOLVED** (1-based only per **SDK**, for a different endpoint) |
| Success envelope | `{"success": true, "Result": {"IsAggregate", "Count", "Columns": [...], "FullCount", "Results": [{"Entities": [...], "Row": {...}}], "ReturnID"}, "Message": null, "MessageID": null, "Exception": null, "ErrorID": null, "ErrorCode": null, "InnerExceptions": null}` | **VERIFIED** (S2) |
| `Count` | "the number of records that the call returns" | **VERIFIED** (S2) |
| `FullCount` | Present in every example (equal to `Count` there); never defined | **UNRESOLVED** (presumably the total before paging) |
| Failure | `success: false`, `Result: null`, `Message` human-readable (e.g. "Query has failed: no such table: Users"), plus `MessageID`, `Exception`, `ErrorID`, `InnerExceptions` | **VERIFIED** (S2) |
| HTTP status of a failed query | Not stated | **UNRESOLVED** |
| Visibility | "Queries only return data that the user has access to." A service user with too few rights can get **fewer roles or users without any error** | **VERIFIED** (S2) |
| Timeout | Queries time out after two minutes | **VERIFIED** (S2) |
| SQL dialect | SQLite (the failure example's exception is `System.Data.SQLite.SQLiteException`); `ORDER BY … COLLATE NOCASE` is used in examples | **VERIFIED** (S2). `LIKE '…%…'` on `Role.Name` is standard SQLite, but no official example uses `LIKE`: **ASSUMED** to work |

## 4. Role table (finding the approver roles)

| Item | Finding | Status |
|---|---|---|
| Columns | `ID` (role UUID, primary key), `Name`, `RoleType` ("PrincipalList, Everybody, or Script"), `ReadOnly` (Boolean), `Description` (localized). The example row also has `DirectoryServiceUuid` and `_MatchFilter` | **VERIFIED** (S3) |
| Query | `SELECT ID, Name, RoleType, ReadOnly, Description FROM Role WHERE Name LIKE 'APP-CYA-ISPSS-SCA-AWS-%-BUApprovers'` | Columns **VERIFIED** (S3); `LIKE` **ASSUMED** (see §3) |
| `RoleType` Everybody / Script | These roles get their members from a rule, not a member list. Whether GetRoleMembers lists the effective members of such roles is not documented | **UNRESOLVED**. Affects the rules (see §8) |
| `LIKE` and `_` | In SQL `_` is a single-character wildcard; the pattern has none, so the mail's pattern is unaffected | n/a |

## 5. GetRole

| Item | Finding | Status |
|---|---|---|
| Endpoint | `POST /Roles/GetRole?Name=<role UUID>` (optional `SuppressPrincipalsList`, `getRights`); permission: system administrator or role management | **VERIFIED** (S5, read 2026-10-21; the operation list did not render on 2026-10-23) |
| Response (reference example, served by the S5 mock on 2026-10-23) | `{"Result": {"DirectoryServiceUuid", "Principals": ["string"], "RoleType", "Uuid", "ReadOnly", "Description", "Name"}}`; no top-level `success` | **VERIFIED** (S5 mock) |
| `Principals` | A list of strings. Whether entries are ids or names, and whether they include groups and roles, is not documented. It carries **no member type**, so it cannot tell users from groups | **UNRESOLVED** |
| Use for counting | The client mail says to use GetRole. Because `Principals` has no type, a valid-approver count cannot rely on it alone. GetRoleMembers (or the documented `/SaasManage/GetRoleMembers`) is needed for types | Design consequence of the above |

## 6. Role members

Two officially documented paths exist, with **different response shapes**:

| Item | Finding | Status |
|---|---|---|
| A. `POST /SaasManage/GetRoleMembers?Name=<role ID>` | Documented in the Role data dictionary to "obtain all child roles" (despite the wording, its example returns a user). Response is a flat Redrock-style envelope: `{"success": true, "Result": {"Count": 1, "Columns": [...], "FullCount": 1, "Results": [{"Entities": [{"Type": "??", "Key": "??"}], "Row": {"Name": "test@mytenant.idaptive.com", "Guid": "cee2bfa4...", "Type": "User"}}]}, ...}` | **VERIFIED** (S3) |
| B. `POST /Roles/GetRoleMembers?name=<role UUID>` | Roles API reference. Its example (served by the S5 mock) is **nested**: `{"Result": {"Result": {"Results": [{"Entities": [...], "Row": [{"Guid", "Name", "Type", "IsEffective", "OrgPath", "OrgId"}]}], "count", "columns", "FullCount", "IsAggregrate", ...}, "success": true, "IsSoftError": true, "Message", ...}, "Error": {"Invalid_Role", "Invalid_Data"}}`: `success` sits **inside** `Result`, `Row` is an **array**, and some names are lower-case (`count`, `columns`, `type`) or misspelled (`IsAggregrate`) | **VERIFIED** (S5 mock) |
| C. SDK | Calls B (`Roles/GetRoleMembers`) with body `{"Name": <role id>}`, expects a **flat** response with top-level `success` and `Result.Results[].Row` as an **object** with `Guid`, `Name`, `Type` (like A) | **VERIFIED (SDK)** |
| Shape conflict | B's documented example vs the SDK's parsing of the same path | **MISMATCHED** (S5 vs SDK) |
| Our `CyberArkClient` | Calls B with `?name=` and body `{"Name"}`, and parses the **flat** shape (requires top-level `success`). Given B's documented nested example, it fails loudly with "missing boolean 'success'" (never a silent 0 members) | **MISMATCHED** with S5's example; matches SDK and S3 |
| Member `Type` values | Documented example: `"User"` (S3). `Group` and `Role` appear only in the SDK, which upper-cases the value before mapping to `USER` / `GROUP` / `ROLE` | `User`: **VERIFIED** (S3); `Group` / `Role`: **VERIFIED (SDK)**; their exact wire spelling: **UNRESOLVED** |
| `IsEffective` | In B's example; meaning (direct vs inherited membership?) not documented | **UNRESOLVED**. Affects "direct members" |
| Paging | Neither path documents paging arguments. A has `Count` / `FullCount` | **UNRESOLVED**; `FullCount > Count` would show truncation |
| Expanding a nested role | Calling the same members API with the child role's id is what S3 describes ("obtain immediate child roles") | **VERIFIED** (S3, path A) |
| Expanding an AD / directory **group** | No official page or SDK function lists a group's members | **UNRESOLVED**: no verified API |

## 7. User status (who counts as an active approver)

| Item | Finding | Status |
|---|---|---|
| User table columns | `ID` (UUID, primary key), `Username`, `DisplayName`, `Email`, `LastLogin`, `LastInvite`, `StatusEnum`, `RiskLevel`, `Status`, `SourceDs`, `SourceDsLocalized`, `SourceDsType`, `DirectoryServiceUuid`, `Forest` | **VERIFIED** (S4) |
| `StatusEnum` | "User status; one of: Created, Suspended, Invited, or Active" | **VERIFIED** (S4) |
| `Status` | The **localized** version of the same status (examples: `Active`, `Invited`, `Not Invited` for StatusEnum `Created`), so not reliable for decisions | **VERIFIED** (S2, S4) |
| `RiskLevel` | `Normal, Low, Medium, High, Unknown, SystemUnavailable`. Not part of the agreed rule | **VERIFIED** (S4); not used |
| Meaning of each status (e.g. is a locked or disabled AD user `Suspended`?) | Not described | **UNRESOLVED** |
| Who is in the table | "all the users **who have accessed the cloud service**". A directory user who never accessed it may have **no row** | **VERIFIED** (S4). Affects the rules (see §8) |
| Lookup | `SELECT ID, Username, DisplayName, Email, LastLogin, Status, StatusEnum FROM User WHERE ID = '<member Guid>'`; that a role member's `Guid` equals `User.ID` is not stated | Columns **VERIFIED** (S4); the id join is **VERIFIED (SDK)** only by usage |
| Agreed rule | Only a found user with `StatusEnum = Active` (any letter case) counts. `Created`, `Invited`, `Suspended`, missing and unknown values do not | Business decision (2026-10-23), consistent with S4 |

## 8. Gaps that affect counting and the outcome rules

| # | Gap | Effect | Blocks implementation? |
|---|---|---|---|
| G1 | Members API shape (§6 A vs B vs SDK) | Wrong shape = no members parsed | **No**, if both documented shapes are accepted and anything else is `CHECK_FAILED`. Which path the tenant answers is for the live test |
| G2 | AD group membership cannot be expanded (§6) | A role with groups may have more approvers than we can see | **No**: groups are reported, never counted; `CANNOT_VERIFY` when they could change a FAIL into a PASS |
| G3 | `RoleType` Everybody / Script (§4) | The member list may not be the real membership | **No**: such a role should be `CANNOT_VERIFY` unless the thresholds are met anyway |
| G4 | Member with no User row (§7) | "Not found" is not "inactive" | **No**: not counted; `CANNOT_VERIFY` if it could change the result |
| G5 | `IsEffective` meaning (§6 B) | "Direct members" may include inherited ones | **No**, but report it per member if present |
| G6 | Redrock paging semantics (§3) | Too few roles silently | **No**: send explicit `args`, compare `Count` with `FullCount`, and treat `FullCount > collected` as `CHECK_FAILED` |
| G7 | Visibility: "queries only return data the user has access to" (§3) | Too few roles or users **with no error** | **No**, but only the client can guarantee the service user's rights. Must be documented as a precondition |
| G8 | Platform token vs Redrock OAuth app (§2) | Login may work but Redrock may refuse | **No** for building; client confirmation |
| G9 | Host `uap…/api` (§1) | Calls may 404 | **No** (configurable); client confirmation |
| G10 | HTTP status of errors (§2, §3) | Error classification | **No**: any non-2xx or `success: false` is `CHECK_FAILED` |

**None of the gaps blocks implementation**, provided the code follows the rules in the right-hand column and never turns an unknown into PASS or FAIL.

## 9. Fixture review (`src/test/resources/official`, see `FIXTURES.md`)

| Fixture | Compared with | Result |
|---|---|---|
| `redrock-user-query.official-derived.json` | S2 User table response | **Matches** (Count/FullCount 44, rows unchanged; the editorial changes listed in FIXTURES.md still apply) |
| `redrock-user-column-data.official-derived.json` | S2 column data | **Matches** (`StatusEnum` Active / Created with `Status` "Not Invited") |
| `redrock-failure.official-derived.json` | S2 unsuccessful call | **Matches** |
| `redrock-role-table.official-derived.json` | S3 Role table response | **Matches** (Count 79, row "admin portal", PrincipalList) |
| `saasmanage-getrolemembers-flat.official-derived.json` | S3 `/SaasManage/GetRoleMembers` response | **Matches** (Row `{Name, Guid, Type: "User"}`) |
| `redrock-user-dictionary.official-derived.json` | S4 User table response | **Matches** (Invited / Active rows) |
| `roles-getrolemembers-nested.official-schema-example.json` | S5 mock `POST /Roles/GetRoleMembers` (2026-10-23) | **Matches byte for byte** |
| `roles-getrole.official-schema-example.json` | S5 mock `POST /Roles/GetRole` (2026-10-23) | **MISMATCHED**: the fixture has an extra top-level `"Error": {}` that the mock no longer returns. No effect on parsing; the fixture should be refreshed when the code is next changed |
| `uap-policies-200…`, `uap-error…`, `uap-policies.public-mock…`, `sca-token…` | — | Use Case 2 only; **not re-verified** in this pass |

Our mock server's own Identity data is fabricated and is not evidence of the contract.

## 10. Client confirmations required

1. **Host:** does `https://8a11f5d4-74cc-451f-b0fd-cfad7d10ddf0.uap.cyberark.cloud/api/Redrock/query` work, or should we use `https://<tenant>.id.cyberark.cloud/` (documented) or `https://<subdomain>.cyberark.cloud/api/idadmin/` (SDK)?
2. **Authentication:** an OAuth confidential-client service user, and confirmation that its **platform token** is accepted by Redrock and Roles. Otherwise, the Redrock OAuth web app (scope `reporting`, Report Management right) from S2.
3. **Permissions:** the service user must be able to see **all** `APP-CYA-ISPSS-SCA-AWS-%-BUApprovers` roles and their members' User rows (role management / system administrator for GetRole and GetRoleMembers per S5; Report Management for Redrock per S2). Missing rights hide data silently (G7).
4. **Members API:** which of `/SaasManage/GetRoleMembers` and `/Roles/GetRoleMembers` the tenant answers, and a sanitized sample response.
5. **Membership content:** whether the approver roles contain AD groups or nested roles, and whether any are `Everybody` / `Script` roles.
6. **Status meaning:** whether a disabled or locked directory user shows as `Suspended`, and whether `Invited` users should ever count. Currently they don't.

---

## Use Case 2 (Access Control Policies): carried over, not re-verified on 2026-10-23

| Item | Value | Source (as of 2026-10-21) |
|---|---|---|
| Endpoint | `GET https://<subdomain>.uap.cyberark.cloud/api/policies` | S1 (host) + SDK (path) |
| Paging | `limit`, `nextToken`; repeat until `nextToken` is missing; a repeated token is an error | SDK |
| Response | `{"results": [...], "nextToken": "...", "total": n}` | SDK |
| Policy status | `metadata.status{status,statusCode,statusDescription}`; values `Active`, `Suspended`, `Expired`, `Validating`, `Error`, `Warning` | SDK |
| Token | Cloud-console and group-assignment policies need the **custom OAuth2 token** (`/oauth2/token/{app_id}`), not the platform token | S1 |

These will be re-verified when Use Case 2 starts.
