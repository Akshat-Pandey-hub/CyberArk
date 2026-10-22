# CyberArk PVWA extraction: implementation audit

Date: 2026-10-22. Scope: `D:\cyberark-integration-poc` as it stands. No source, test, schema or configuration file
was changed during this audit (SHA-256 of every project file outside `target/` was recorded before and after; the
sets are identical). Only `target/` (normal build output) and this report are new.

**No real CyberArk PVWA was contacted. Nothing in this report is live validation.**

References: the request document "CyberArk PVWA Read-Only API Access Request – KeyForge" (Oct 22, 2026), and
the official PAM Self-Hosted REST API pages listed in `docs/API_CONTRACT_PVWA.md`. On 2026-10-22 I re-read the
overview, Logon, Logoff, Verify, Server and Get all Safes pages. The site then returned 403 (rate limit), so the
other endpoint pages rely on the reading recorded earlier the same day in that contract.

---

## 1. Build and test results (observed)

Environment: Temurin OpenJDK 17.0.20, Maven 3.9.14 (offline `-o`, no dependency changes), project `release 17`.

| Run | Command | Result |
|---|---|---|
| A | `mvn -o clean test` (no database variables) | BUILD SUCCESS. 127 tests, 0 failures, 0 errors, **7 skipped** (all 7 are `PostgresIntegrationTest`, skipped by design when `CYBERARK_IT_PG_*` is unset) |
| B | `mvn -o clean package` with `CYBERARK_IT_PG_*` pointing at a throwaway PostgreSQL 18.1 (created with `initdb` in a temp folder, port 55432, deleted afterwards) | BUILD SUCCESS. **127 tests, 0 failures, 0 errors, 0 skipped** (`PostgresIntegrationTest` 7/7) |

No compilation errors, test failures or packaging problems.

**JAR:** `target/cyberark-poc.jar` (3,594,261 bytes), built by maven-shade 3.6.0.
- `Main-Class: com.keyforge.cyberarkpoc.Main`; it runs with `java -jar`.
- It bundles its runtime dependencies (Jackson databind, the PostgreSQL JDBC driver with `META-INF/services/java.sql.Driver`).
- It **also bundles the mock server** (11 classes in `mock/`) and the earlier ISPSS use-case checks (11 classes in `check/`). Neither is part of the deliverable (see finding P2-2).

**Manual run of the built jar** (the jar itself, not the test code), against the mock on 127.0.0.1:8300 and the
throwaway PostgreSQL, schema `audit_e2e`:

| Step | Result |
|---|---|
| `pvwa-verify` | exit 0, SUCCESS, 1 logon, logoff ok |
| `pvwa-safes` | exit 0, SUCCESS, 30 extracted / 30 inserted, 2 pages, reported_total 30, complete |
| `pvwa-accounts` (run 1) | exit 0, SUCCESS, 120 extracted / 120 inserted, 3 pages, complete |
| `pvwa-accounts` (run 2) | exit 0, SUCCESS, 0 inserted / 120 updated (upsert in place, no duplicates) |
| `start-rest`, no credentials / wrong password | 401 / 401 |
| `start-rest`, POST, unknown route | 405 / 404 |
| `start-rest`, `GET /cyberark-extract/pvwa/accounts` | 200, header `X-KF-Run-Status: SUCCESS`, 120 records, no `secret` field or secret value |
| PostgreSQL | tables `kf_cyberark_safe` (30 rows), `kf_cyberark_account` (120 rows, 120 distinct `record_id`), `kf_extraction_run` (4 rows, all SUCCESS; Verify writes no row) |
| Secret check in PostgreSQL | 0 account rows with a `secret` field, a nested `Password` or any mock secret value |
| Unknown field | `MOCK-Safe-30.mockTenantSpecificField` stored unchanged |
| Lineage | `source_system=cyberark`, `source_interface=pvwa-rest`, `source_object_type=PVWA.Account`, 64-char `record_hash`, `is_deleted=false` |
| Leak scan | console output, REST body, REST server log and every run-log `error_message`: 0 occurrences of a session token (`mock-pvwa-session-…`), the vault password, the DB password, the REST password or a secret value |

---

## 2. Endpoint matrix

Legend: ✅ implemented and tested against the mock · ❌ not implemented · ⚠️ implemented with an open question.
"Mock-tested" means tested against our own mock, which was written from the official docs. It is not CyberArk.

| # | Endpoint (document → official) | Status | Class / method | Contract match | Paging | Permission / config documented | Defects, gaps, assumptions |
|---|---|---|---|---|---|---|---|
| 1 | Logon `POST /API/Auth/<m>/Logon` → `POST /API/auth/{Cyberark\|LDAP\|RADIUS\|Windows}/Logon/` | ✅ | `PvwaClient.logon()` (private; called by `ensureSession`) | Path, POST, JSON `{username,password}`, token read as a JSON string: match | n/a | `CYBERARK_PVWA_AUTH_METHOD`, `_USERNAME`, `_PASSWORD` in README | RADIUS challenge/MFA not supported (document §3 asks for an MFA exemption). Windows logon is sent as username/password per the docs page; real Windows auth is often IIS-integrated: **unverified**. `concurrentSession` not sent (fine for one session per run). Renewal after 18 min (doc default 20) does logoff + logon, so a long run can have more than one session, one at a time |
| 2 | Logoff `POST /API/Auth/Logoff` → `POST /API/Auth/Logoff/` | ✅ | `PvwaClient.logoff()` via `close()` | Match (Authorization header, no body) | n/a | README | A failed logoff is reported (`logoff` field), not thrown |
| 3 | Health check `GET /API/Server/Verify` → official `GET /WebServices/PIMServices.svc/Verify/` (token required) | ⚠️ | `PvwaClient.verify()`; route `pvwa/verify`; CLI `pvwa-verify` | Matches the **official** page, **not the document** | n/a | README "Health check, unresolved" | **Discrepancy D1** (below). Needs a logon, so it is not the "no credentials" connectivity test of document §8. Writes no run-log row |
| 4 | Accounts `GET /API/Accounts` | ✅ | `PvwaExtraction.accounts()` → `OffsetPager.fetchAll(…, "/API/Accounts", limit 50, id "id")` → `ExtractionRunner.run` | Path, GET, `value`/`count`/`nextLink`: match | offset/limit, default 50, configurable 1–1000 | List Accounts noted in code/contract; README mentions `MaxDisplayedRecords` | `secret` dropped. `MaxDisplayedRecords` capping behaviour and `count` semantics **unverified** (P2-5). No `filter`/`savedfilter` used (full inventory) |
| 5 | Safes `GET /API/Safes` → `GET /API/Safes/` | ✅ | `PvwaExtraction.safes()` → `OffsetPager` (limit 25, id `safeUrlId`) | Match | offset/limit, default 25 | Contract: only safes the user is a member of | `extendedDetails` left at its documented default (true). `nextLink` content is not followed; our own offset is used |
| 6 | Safe members `GET /API/Safes/{safe}/Members` → `GET /API/Safes/{SafeUrlId}/Members/` | ❌ | Only an allow-list entry in `PvwaClient.READ_PATHS` | — | — | Contract only | Not implemented. Predefined users are excluded unless `includePredefinedUsers eq true` |
| 7 | Target platforms `GET /API/Platforms/Targets` → `GET /API/platforms/targets/` | ❌ | Allow-list entry only | — | none documented | Contract only | Not implemented. Response is `{Platforms, Total}`, not `value`/`count` (needs its own reader) |
| 8 | Platform details `GET /API/Platforms/{id}` → `GET /API/Platforms/{PlatformName}/` | ❌ | Allow-list entry only | — | n/a (one call per platform) | Contract only | Not implemented |
| 9 | Users `GET /API/Users` → `GET /API/Users/` | ❌ | Allow-list entry only | — | `pageOffset`/`pageSize` (differs from offset/limit) | Contract: **Audit users** needed | Not implemented. `ExtendedDetails=true` needed for enabled/suspended/groups |
| 10 | Groups `GET /API/UserGroups` → `GET /API/UserGroups/` | ❌ | Allow-list entry only | — | offset/limit | Contract: **Audit users** needed | Not implemented. `includeMembers=true` needed |
| 11 | Discovered accounts `GET /API/DiscoveredAccounts` → `GET /API/DiscoveredAccounts/` | ❌ | Allow-list entry only | — | offset/limit, default 100, max 1000 | Contract: **Vault Admins or PVWAAccountsFeedAdmins** | Not implemented |
| 12 | Account activity (optional) → 1st gen `GET /WebServices/PIMServices.svc/Accounts/{id}/Activities/` | ❌ | Allow-list entry only | — | n/a (one call per account) | Contract: permission not stated | Not implemented |

**Summary: 5 of 12 implemented (Logon, Logoff, Verify, Accounts, Safes); 7 not implemented.**

### Discrepancies between the request document and the official docs

| # | Document | Official docs | How the code handles it |
|---|---|---|---|
| D1 | Health check `GET /API/Server/Verify`; §8 test "needs no credentials" | `GET /WebServices/PIMServices.svc/Verify/`, Authorization **mandatory**. (Community psPAS uses `/API/verify/` on newer versions.) | Official path used; documented as unresolved pending the PVWA version |
| D2 | Audit users "only if activity/audit data is in scope" | Users and UserGroups require **Audit users** | Not yet relevant (endpoints not built); must be raised with the client |
| D3 | Only List accounts / View safe members | Discovered accounts needs **Vault Admins or PVWAAccountsFeedAdmins** | Not yet relevant; must be raised with the client |
| D4 | "Account activities" | Only 1st-gen, per account | Not yet built |
| D5 | One page size "1000 or less" | Defaults differ per endpoint; Users uses `pageOffset/pageSize`; Platforms has no paging | Per-endpoint defaults in code (Safes 25, Accounts 50) |
| D6 | — | Accounts response includes `secret` | Removed by `SecretRedactor` |
| D7 | — | `GET /WebServices/PIMServices.svc/Server/` returns the vault version (read-only) | Not used, not in the allow-list; could answer document §7 question 1 automatically |

---

## 3. REST routes and PostgreSQL storage

**Routes** (`ExtractionRestServer`, `start-rest`, default `127.0.0.1:8210`, HTTP Basic auth `REST_USERNAME`/`REST_PASSWORD`, GET only, one run at a time → 409):

| Route | Does |
|---|---|
| `GET /cyberark-extract` | lists routes |
| `GET /cyberark-extract/pvwa/verify` | logon, Verify, logoff; returns the Verify JSON; stores nothing |
| `GET /cyberark-extract/pvwa/safes` | extracts all Safes, stores them, returns the run summary **and all records** |
| `GET /cyberark-extract/pvwa/accounts` | same for Accounts |

HTTP status: SUCCESS / COMPLETED_WITH_FAILURES / INCOMPLETE → 200, CONFIG_ERROR → 500, FAILED → 502 (unexpected
handler error → 500), plus header `X-KF-Run-Status`. The CLI commands `pvwa-verify`, `pvwa-safes` and
`pvwa-accounts` run the same code; their exit codes are 0 / 6 / 7 / 2 / 1.

**Storage** (`RawRecordRepository`, `RunLedger`, `DbConfig`), plain JDBC, Part 2's `PG_*` variables, default schema `iiq_native_part2`:
- `<schema>.kf_cyberark_<entity>`: `record_id uuid` PK (deterministic from entity + CyberArk id), `source_id`, `payload jsonb` (full redacted record, unknown fields kept), `record_hash`, and the lineage columns `source_system`, `source_interface`, `source_object_type`, `extraction_run_id`, `extracted_at`, `is_deleted`, `deleted_at`.
- Upsert `ON CONFLICT DO UPDATE … RETURNING (xmax = 0)` to tell inserts from updates.
- `<schema>.kf_extraction_run`: Part 2's exact DDL; exactly one row per extraction run (SUCCESS, INCOMPLETE, COMPLETED_WITH_FAILURES or FAILED).
- Tables and schema are created if absent (`CREATE … IF NOT EXISTS`); existing tables are never altered.
- **Verified against a real PostgreSQL 18.1:** inserts, re-run updates in place, INCOMPLETE and FAILED runs logged once each, no secrets stored, unknown fields kept, lineage populated.
- **Not implemented:** marking records deleted (`is_deleted` is never set to true; see P1-2). There's no PostgreSQL SSL option (P2-6).

**Configuration:** environment variables only (no settings file). PVWA, paging and database settings are validated at start, with clear `CONFIG_ERROR` messages. The vault, DB and REST passwords are masked in every `toString()`.

**Logging:** console only (`System.out`/`System.err`); no logging framework, no log file. Extraction code prints only the masked config line and the JSON summary.

**Error handling:** CyberArk errors are classified (AUTHENTICATION, HTTP_STATUS, INVALID_RESPONSE, TRANSPORT). Unexpected errors become JSON `FAILED`/`INTERNAL`. The session is always logged off, and a run-log write failure never hides the original error. Covered by `RestFailureHandlingTest` and `PostgresIntegrationTest`.

---

## 4. Security findings

| Check | Result | Evidence |
|---|---|---|
| HTTPS required | ✅ `PvwaConfig` rejects any non-https URL except localhost | `PvwaConfigTest.httpsIsRequiredExceptForLocalhost` |
| Certificate validation not disabled | ✅ by code inspection: JDK `HttpClient` with its default `SSLContext`; no TrustManager, HostnameVerifier or disable flag anywhere. Redirects are not followed | grep of `src/main`; **not exercised by a TLS test** |
| Client's internal CA | ⚠️ No setting. The standard JVM flags `-Djavax.net.ssl.trustStore=…` work with this client, but that is undocumented and untested | P2-1 |
| Session tokens not logged | ✅ Tokens appear only in the `Authorization` header. `PvwaClient.sanitize` masks every token and the password in any outgoing text | manual leak scan = 0; `AccountsExtractionTest.sanitizeMasksTheVaultPasswordAndSessionTokens` |
| Credentials in source control | ✅ None found (only the fabricated mock values). **But the project is not under source control at all** (no git repository) | P2-7 |
| Secret values removed before return/store | ✅ `SecretRedactor` drops any `secret`/`password` field at any depth, before the data reaches REST, the DB or error text | PG test + manual check = 0 secrets; `SecretRedactorTest` |
| Redaction limit | ⚠️ Name-based: only fields named `secret`/`password` (any case). A secret under any other field name would not be removed. Error-text masking covers password/secret/token/Authorization/Bearer only | inherent; documented |
| Unknown attributes preserved | ✅ The whole redacted record is stored in `payload` | PG test + manual check |
| Pagination does not silently truncate | ✅ mostly: a count mismatch, no progress or the page limit marks the run INCOMPLETE. ⚠️ If PVWA omits `count` *and* silently caps results, a cap would go unnoticed. `MaxDisplayedRecords` behaviour is unverified | `OffsetPagerTest` (9 tests) |
| Errors and partial results reported accurately | ✅ Status, notes and counts appear in JSON and in the run log; exactly one run-log row per run | PG tests |
| Only read-only CyberArk operations | ✅ PVWA sends POST only for Logon and Logoff; every GET must match the `READ_PATHS` allow-list, so retrieve/verify/change/reconcile/unlock/check-in cannot be called | `PvwaClientTest.onlyDocumentedReadPathsCanBeCalled` |
| Path segments | ⚠️ The allow-list uses `[^/]+` for `{safe}`, `{platform}` and `{id}`, and the segment is not URL-encoded or validated by the client. Not exploitable today (only GET is possible, and no code passes a segment yet), but it must be handled when Safe members/platforms are built | P3-4 |
| REST service transport | ⚠️ Plain HTTP with Basic auth. Safe on the default `127.0.0.1`; if `REST_HOST` is opened to the network, credentials and data travel unencrypted | P2-3 |

---

## 5. Bugs and missing functionality, by priority

**P1: needed for the deliverable to be correct**
1. **Seven of twelve endpoints not implemented:** Safe members, Target platforms, Platform details, Users, Groups, Discovered accounts, Account activity.
2. **Deleted CyberArk objects stay "current" in PostgreSQL.** `is_deleted` is never set. A Safe or Account removed in CyberArk keeps `is_deleted=false` forever, and the Assurance tool cannot tell it apart from a live one. SailPoint Part 2 has `SoftDeleteSweeper` for exactly this; the CyberArk service has no equivalent.
3. **Health-check path unresolved (D1).** It must be confirmed with the client's PVWA version; the document's §8 test must also be corrected.
4. **No official-example PVWA fixtures.** Every PVWA test uses our own mock. The parsing has not been checked against CyberArk's published example responses copied verbatim (the ISPSS part has such fixtures; PVWA has none).

**P2: needed for deployment on the client's server**
1. No documented or tested way to trust the client's internal CA (document §2 asks for the CA chain).
2. The production jar contains the mock server, a `mock` command that prints mock credentials, and the out-of-scope `check` use-case commands.
3. REST interface is plain HTTP with Basic auth (fine on localhost only).
4. REST extraction routes return every record in one response body. For a large vault (tens of thousands of accounts) this is a very large, pretty-printed body held in memory.
5. `count` semantics and the `MaxDisplayedRecords` cap are unverified. If `count` were per page, every multi-page run would be marked INCOMPLETE (safe, but noisy); if PVWA caps results without reporting it, data could be missing.
6. No PostgreSQL SSL setting (e.g. `sslmode`) for a client database that requires TLS.
7. No source control: there is no history, and no way to prove which code was delivered.

**P3: quality and housekeeping**
1. README: the top section is stale and contradictory ("Out of scope: PostgreSQL tables"), and the ISPSS use-case material is mixed with the PVWA service.
2. The Postman collection covers only the ISPSS mock, not the PVWA REST routes.
3. `record_hash` is computed but unused, so every re-run reports unchanged rows as "updated".
4. URL-encode and validate path segments before Safe members and platform details are added.
5. `extraction_run_id` is `text` in entity tables but `uuid` in the run log (minor type mismatch).
6. Verify writes no run-log row (by design, but undocumented in the run-log description).
7. Windows and RADIUS logon have not been verified; RADIUS with an MFA challenge cannot work unattended.

---

## 6. What can be tested locally vs what needs the client's environment

| Category | What | Status |
|---|---|---|
| A. Unit tests, no server | Config validation, redaction, error sanitizing, SQL text, hashing, ids, HTTP status mapping, the ISPSS use-case logic | runs everywhere; passing |
| B. Mock / simulated HTTP | PVWA logon/logoff/renewal/401 retry, allow-list, paging (all pages, wrong count, ignored offset, page limit, missing id, 403, malformed), Accounts redaction, REST auth/409/failure JSON | runs everywhere; passing. **Proves our logic only, not CyberArk compatibility.** The mock is a test aid, not a deliverable |
| C. Real PostgreSQL | Table creation, insert/update, run log, no secrets stored, failure logged once | passing against a throwaway PostgreSQL 18.1 (7 tests + manual jar run). Not run against the client's database |
| D. Live PVWA | Real logon method, TLS/CA, the real Verify path, real field names, `count` semantics, `MaxDisplayedRecords`, permissions (403s), session length, rate limits, real data volume | **Not done. Requires** the PVWA URL, firewall rule, service account, permissions, CA chain and version from the client |

---

## 7. Plan for the next stage

Each step is small, reviewed before the next, and tested in categories A–C.

1. **Data correctness for what exists**
   - Add official-example fixtures for Safes and Accounts, copied verbatim from the official pages, with contract tests (P1-4).
   - Add a Part 2-style soft-delete sweep. It runs only when a run is complete and SUCCESS, never on INCOMPLETE/FAILED or an empty result (P1-2). This needs your agreement because it changes how rows are marked; the schema itself is unchanged.
2. **Remaining endpoints, one per step**, each with an official-example fixture, mock tests and a PostgreSQL test:
   - Safe members (per stored Safe, URL-encoded `safeUrlId`)
   - Target platforms + Platform details
   - Users (`ExtendedDetails=true`, `pageOffset`/`pageSize`)
   - Groups (`includeMembers=true`)
   - Discovered accounts (permission errors reported as FAILED with the reason)
   - Account activity (optional, per account)
3. **Deployment readiness**
   - Document and test the truststore launch option (P2-1).
   - Add a PostgreSQL SSL setting (P2-6).
   - Make the REST response size safe: summary by default, records optional or paged (P2-4).
   - Build the delivered jar without the mock and the `check` commands (P2-2).
   - Put the project under git (P2-7).
4. **Handover package**
   - Settings template.
   - Linux run steps.
   - Permission list (with D2/D3).
   - Corrected §8 connectivity test (D1).
   - A Postman collection for the REST routes.
   - Cleaned-up README (P3-1, P3-2).
5. **First live run (client side)**: `pvwa-verify`, then each extraction, in their non-production PVWA if one exists (document §7 question 5). Results are fed back to fix any contract differences.
