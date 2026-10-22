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

Each table has one column per documented response field, under exactly the same name (quoted in SQL, e.g.
`"safeName"`); nested objects such as `creator` or `secretManagement` are `jsonb`. Two more columns:
`record_uuid` (a random UUID given to the row when it is first stored) and `extracted_at`. CyberArk's own id
(`safeUrlId`, account `id`) is unique, so a re-run updates the row and keeps its `record_uuid`. A response field
that has no column is listed in the run's `fields_without_column`. Fields named `secret` or
`password` are removed at any depth before anything is returned or stored.

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

## How "valid approver" is decided in this phase

A member counts only if it is a user, a `User` row exists, and its `StatusEnum` is `Active`
(case-insensitive). `StatusEnum` is the documented, non-localized status column (Created, Suspended,
Invited, Active). The localized `Status` column is shown in the report but never used for the
decision, not even as a fallback. A missing `StatusEnum` means **not counted**
(`STATUS_UNKNOWN`), never guessed as valid. Whether Invited or Created users should count is an open
business decision; under the current rule they don't. Nested roles are expanded. Groups are listed as
unresolved and not counted, because no verified API for group members is known. Any failed
call fails the whole check, so a failure can never look like a clean result.
