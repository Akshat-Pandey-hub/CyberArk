# CyberArk integration POC (mock-backed)

A small, isolated proof that the CyberArk connector and the two client use cases can be
built and tested **without CyberArk account access**. It is separate from the SailPoint
Part 1 / Part 2 projects and touches neither of them.

> **All data in this project is fabricated.** The mock server is not CyberArk. Every mock
> response carries the header `X-Mock-Data: FABRICATED - not a CyberArk tenant response`
> and a top-level `_mock` field. Which fields are verified and which are assumed is recorded
> in [docs/API_CONTRACT.md](docs/API_CONTRACT.md).

## What is here

| Part | Where |
|---|---|
| API contract (verified vs assumed, with sources) | `docs/API_CONTRACT.md` |
| Java API client (config, token, the five calls, error handling, parsing) | `src/main/java/com/keyforge/cyberarkpoc/client`, `.../config` |
| Use case 1: approver roles need at least 3 valid approvers | `.../check/ApproverGroupCheck.java` |
| Use case 2: policies in Error or Warning | `.../check/PolicyHealthCheck.java` |
| Local mock CyberArk + fabricated demo data | `.../mock` |
| Postman collection + mock environment | `postman/` |
| Automated tests | `src/test/java` |

Out of scope in this phase: PostgreSQL tables, the existing database, SailPoint data or
identity matching, deployment, and notifications.

## PVWA extraction service (in progress)

Extracts read-only CyberArk PVWA data, as listed in the KeyForge "PVWA Read-Only API Access Request"
document, into PostgreSQL. Each record is also returned as JSON. The API contract for every endpoint (official
CyberArk documentation) is in [docs/API_CONTRACT_PVWA.md](docs/API_CONTRACT_PVWA.md).

**Done so far:**
- logon / logoff and the Verify health check
- **Safes** (`GET /API/Safes/`, all pages)
- **Accounts** (`GET /API/Accounts`, all pages, documented default page size 50). Secret values are removed. PVWA's
  `MaxDisplayedRecords` setting can cap the number of accounts returned; a reported `count` that differs from the
  records received marks the run INCOMPLETE.

**Health check, unresolved:** the request document uses `GET /API/Server/Verify`. The official latest
documentation shows `GET /WebServices/PIMServices.svc/Verify/` (with the Authorization header required), and the
community psPAS module uses `/API/verify/` on newer versions. The code uses the official path. Which one applies
depends on the client's PVWA version (document section 7, question 1); it is not changed until that is confirmed.

**Errors and secrets:** every error message is sanitized before it is returned or printed:
- the vault password and session tokens are masked
- `password` / `secret` / `token` / `Authorization` / `Bearer` values are masked
- JSON error bodies are redacted first

Any unexpected error still produces a JSON response (`status: FAILED`, `error_kind: INTERNAL`) and closes the
session.

| Setting | Meaning |
|---|---|
| `CYBERARK_PVWA_BASE_URL` | `https://<pvwa-fqdn>/PasswordVault` (https required, except localhost) |
| `CYBERARK_PVWA_AUTH_METHOD` | `CyberArk` (default), `LDAP`, `RADIUS` or `Windows` |
| `CYBERARK_PVWA_USERNAME`, `CYBERARK_PVWA_PASSWORD` | the read-only service account |
| `CYBERARK_PVWA_PAGE_SIZE` | optional, 1 to 1000; default is each endpoint's documented default (Safes: 25) |
| `CYBERARK_PVWA_THROTTLE_MS` | pause between pages, default 100 |
| `PG_HOST`, `PG_PORT`, `PG_DATABASE`, `PG_USERNAME`, `PG_PASSWORD`, `PG_DEST_SCHEMA` | the PostgreSQL database (schema default `cyberark`) |
| `REST_USERNAME`, `REST_PASSWORD`, `REST_HOST`, `REST_PORT` | `start-rest` Basic auth and address (default `127.0.0.1:8210`) |

| Command / route | Does |
|---|---|
| `pvwa-verify` / `GET /cyberark-extract/pvwa/verify` | logon, `GET /WebServices/PIMServices.svc/Verify/`, logoff; stores nothing |
| `pvwa-safes` / `GET /cyberark-extract/pvwa/safes` | all Safes into `<schema>.pvwa_safe`; the REST route also returns the records |
| `pvwa-accounts` / `GET /cyberark-extract/pvwa/accounts` | all Accounts (secrets removed) into `<schema>.pvwa_account` |
| `pvwa-target-platforms` / `GET /cyberark-extract/pvwa/target-platforms` | all target platforms (one response, no paging) into `<schema>.pvwa_target_platform` (key `PlatformID`; column names follow the documented example's PascalCase) |
| `pvwa-platform-details` / `GET /cyberark-extract/pvwa/platform-details` | the details of every target platform (one call per platform) into `<schema>.pvwa_platform_detail` (key `PlatformID`; `Properties` jsonb) |
| `pvwa-users` / `GET /cyberark-extract/pvwa/users` | all Vault users with `ExtendedDetails=true` (paged with `pageOffset`/`pageSize`, default 1000) into `<schema>.pvwa_user` (key `id`; needs **Audit users**; only users at the caller's level or lower are returned) |
| `pvwa-user-groups` / `GET /cyberark-extract/pvwa/user-groups` | all user groups with `includeMembers=true` (offset/limit, default 1000) into `<schema>.pvwa_user_group` (key `id`; needs **Audit users**; visibility also depends on `HideVaultUsersTree`) |
| `pvwa-discovered-accounts` / `GET /cyberark-extract/pvwa/discovered-accounts` | the **pending** discovered accounts (offset/limit, default 100, max 1000) into `<schema>.pvwa_discovered_account` (key `id`; needs **Vault Admins or PVWAAccountsFeedAdmins**; every run's notes state that onboarded accounts and anything outside the discovery scope are not listed) |
| `pvwa-safe-members` / `GET /cyberark-extract/pvwa/safe-members` | the members of every Safe into `<schema>.pvwa_safe_member` (key `safeUrlId` + `memberId`; needs View Safe Members; predefined users not requested) |

**Columns come from the records CyberArk actually returns, not from a list in the code** (`store/GenericRecordStore`).
- **Names:** every top-level field gets its own column under exactly the same name and letter case (quoted in SQL,
  e.g. `"safeName"`). Nested objects and arrays are `jsonb`. A field that only the client's PVWA sends is stored too.
- **Types:** they follow the values (`boolean`, `bigint`, `numeric`, `text`, `jsonb`). A text value is never turned into
  a number.
- **Conflicts:** if values of one field disagree, the column is widened (e.g. number + text gives `text`; anything +
  object gives `jsonb`). A record is never rejected because of a type, and no value is lost.
- **Nulls:** a column first seen only as null starts as `text` and takes the field's real type once a value arrives.
- **Schema changes:** made under a per-table lock and listed in the run's `schema_changes`.
- **Service columns:** `record_uuid` (random, kept on re-runs) and `extracted_at`.
- **Key:** CyberArk's own id (`safeUrlId`, account `id`, …) has a unique index, so a re-run updates the row.
- **Missing values:** a field that disappears is cleared, and missing and `null` are both SQL `NULL`.
- **Names that can't be columns:** a name over 63 bytes or equal to a service column is kept in `_extra_fields`
  (`jsonb`).
- **Secrets:** fields named `secret` or `password` are removed at any depth before anything is returned or stored.

The database user must own or be allowed to alter these tables. The service creates them, so that is normally the case.

Run statuses:
- **SUCCESS**
- **INCOMPLETE**: e.g. the reported `count` differs from the records received, or paging made no progress
- **COMPLETED_WITH_FAILURES**: some records failed to store, or had no id
- **FAILED**: the CyberArk call or the database failed

CLI exit codes: 0, 7, 6, 1 (and 2 for configuration errors).

**Verified so far:** only against the local mock and a local PostgreSQL. Nothing has been verified against a
real PVWA.

PostgreSQL integration tests run only when `CYBERARK_IT_PG_HOST`, `CYBERARK_IT_PG_PORT`,
`CYBERARK_IT_PG_DATABASE`, `CYBERARK_IT_PG_USERNAME` and `CYBERARK_IT_PG_PASSWORD` point at a **test**
database (each test uses its own throwaway schema and drops it afterwards). Without them they are reported
as skipped.

## Requirements

Java 17 and Maven 3.9. On this machine the JDK needs
`-Djdk.net.unixdomain.tmpdir=<short folder>` or it fails with "Unable to establish loopback
connection". The Maven test setup already passes it; the commands below pass it explicitly.

## Build and test

```bash
cd D:/cyberark-integration-poc
mvn test
mvn package -DskipTests
```

`mvn test` runs every test against an in-process mock on a random port. `mvn package`
produces `target/cyberark-poc.jar`.

## Run the mock

```bash
java -Djdk.net.unixdomain.tmpdir=D:/cyberark-integration-poc/target -jar target/cyberark-poc.jar mock 8300
```

It listens on `127.0.0.1:8300` only, prints its endpoints, and stops on Ctrl+C.
Mock-only credentials: `client_id=mock-client`, `client_secret=mock-secret`.

| Call | Mock path |
|---|---|
| Login | `POST /oauth2/platformtoken` (form) |
| Role search | `POST /api/Redrock/query` with `... FROM Role WHERE Name LIKE '...'` |
| Role details | `POST /api/Roles/GetRole?Name=<roleId>` |
| Role members | `POST /api/Roles/GetRoleMembers?name=<roleId>` (body `{"Name": "<roleId>"}` also accepted) |
| User lookup | `POST /api/Redrock/query` with `... FROM User WHERE ID='...'` |
| Policies | `GET /api/policies?limit=50&nextToken=<token>` |

The demo data covers: a sufficient role, a role with a user whose status is missing, a role
with a suspended user, a role with a group member, a role filled up by a nested role (which
also contains a member with no user row), a non-matching Azure role, and 7 policies over 3
pages (Active, Error, Warning, Suspended, Expired, Validating, Error).

## Run the checks against the mock

With the mock running, in a second terminal (PowerShell):

```powershell
$env:CYBERARK_IDENTITY_BASE_URL="http://127.0.0.1:8300/api"
$env:CYBERARK_UAP_BASE_URL="http://127.0.0.1:8300/api"
$env:CYBERARK_TOKEN_URL="http://127.0.0.1:8300/oauth2/platformtoken"
$env:CYBERARK_CLIENT_ID="mock-client"
$env:CYBERARK_CLIENT_SECRET="mock-secret"
java -Djdk.net.unixdomain.tmpdir=D:/cyberark-integration-poc/target -jar target/cyberark-poc.jar check
```

Exit codes: `0` checks completed (findings may exist), `1` a CyberArk call failed, `2` bad
configuration. The report goes to the console only.

| Variable | Meaning |
|---|---|
| `CYBERARK_IDENTITY_BASE_URL` | Base for Redrock and Roles calls. The client mail uses `https://<sub>.uap.cyberark.cloud/api`; the SDK uses `https://<tenant>.id.cyberark.cloud`. |
| `CYBERARK_UAP_BASE_URL` | Base for policies, e.g. `https://<sub>.uap.cyberark.cloud/api` |
| `CYBERARK_TOKEN_URL` | Optional. Defaults to `<identity base>/oauth2/platformtoken` |
| `CYBERARK_CLIENT_ID`, `CYBERARK_CLIENT_SECRET` | Service user credentials (never printed) |
| `CYBERARK_TIMEOUT_SECONDS` | Optional, default 30 |

Only `https` is accepted, except plain `http` to localhost for the mock.

## Run the Postman collection

With the mock running:

```bash
postman collection run postman/CyberArk-Mock.postman_collection.json -e postman/mock.postman_environment.json
```

Or import both files into the Postman app. The collection logs in, finds the approver
roles, reads the first role's details and members, looks up a user member, and reads the
policies page by page. For a real tenant later, make a copy of the environment with the
real URLs and credentials. Don't commit real credentials.

## Use case 1: approver group validation (`ispss-approver-groups`)

`java -jar cyberark-poc.jar ispss-approver-groups` or `GET /cyberark-extract/ispss/approver-groups` (via
`start-rest`). It uses its own Identity login, separate from PVWA. The contract and its open questions are in
[docs/API_CONTRACT.md](docs/API_CONTRACT.md).

| Setting | Meaning |
|---|---|
| `CYBERARK_IDENTITY_BASE_URL` | Identity host for Redrock and Roles. Documented: `https://<tenant>.id.cyberark.cloud`. The client mail's `https://<id>.uap.cyberark.cloud/api` is unconfirmed |
| `CYBERARK_TOKEN_URL` | optional; default `<identity base>/oauth2/platformtoken` |
| `CYBERARK_CLIENT_ID`, `CYBERARK_CLIENT_SECRET` | the OAuth confidential-client service user (never printed or stored) |
| `CYBERARK_ROLE_MEMBERS_API` | `roles` (default, `/Roles/GetRoleMembers`) or `saasmanage` (`/SaasManage/GetRoleMembers`); both response shapes are accepted |
| `CYBERARK_APPROVER_ROLE_PATTERN` | default `APP-CYA-ISPSS-SCA-AWS-%-BUApprovers` |
| `CYBERARK_MIN_APPROVERS` | default 3 |
| `CYBERARK_REDROCK_PAGE_SIZE` | default 1000 |
| `PG_*` | as for the PVWA extraction |

How it works:
- **Role search:** a paged Redrock search for the matching roles. A `FullCount` that doesn't match the roles received,
  or paging that makes no progress, makes the run `INCOMPLETE`.
- **Per role:** `GetRole`, then the role's direct members, then a User lookup per user.
- **Nested roles:** expanded only when the Role table shows them as `PrincipalList`.

Per role:
- **Direct members:** all distinct members of any type, counted by type.
- **Verified active users:** distinct users, directly or through an expanded nested role, whose `StatusEnum` is
  `Active`. `Created`, `Invited`, `Suspended`, a missing status or an unknown value do not count. The localized
  `Status` is never used.

| Outcome | When |
|---|---|
| `PASS` | at least 3 direct members **and** at least 3 verified active users |
| `FAIL` | a threshold is definitely missed |
| `CANNOT_VERIFY` | unresolved members (groups, nested roles not expanded, users without a User row or status, an incomplete or non-PrincipalList member list) could still change the result |
| `CHECK_FAILED` | an API call for that role failed or answered something malformed |

**Visibility:** every result carries a visibility note. Redrock only returns what the service user may see, so an empty
or short result is never proof that a role or member doesn't exist.

**Tables:**
- `ispss_role` (key `ID`)
- `ispss_role_member` (key `role_id` + `Guid`)
- `ispss_user` (key `ID`)
- `ispss_approver_group_result` (latest result per `role_id`)

Each has a `record_uuid` and `extracted_at`. Nothing in this use case has been run against a real tenant.
