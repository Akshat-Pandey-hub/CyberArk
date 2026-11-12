# CyberArk extraction service: handover guide

**What it is:** one Java service that logs on to CyberArk PVWA (PAM Self-Hosted), reads the data listed in the
"CyberArk PVWA Read-Only API Access Request" document through the official REST APIs, removes secret values,
stores every record in PostgreSQL, and logs off. It runs as a command (for a scheduler) or as a small REST service
(for Postman). It makes no change in CyberArk: only Logon and Logoff are POST calls, and every other call is a GET
on a fixed list of read paths.

**Status, honestly:**
- **Tested:** against a local mock CyberArk and a real PostgreSQL. There are 239 automated tests, plus manual Postman
  and pgAdmin checks.
- **Not tested:** it has **not** been run against a real CyberArk. The first run on the client's PVWA is the real test
  (see §6 and §11).

## 1. What is in the package

| File | Purpose |
|---|---|
| `cyberark-extract.jar` | The service, with its libraries (Jackson, PostgreSQL JDBC driver). **No test mock inside.** |
| `cyberark-extract.env.example` | Settings template. Copy it to `cyberark-extract.env` and fill it in |
| `run-extractions.sh` | Runs the health check and all 8 extractions once, with one log per command (for cron) |
| `CyberArk-Extraction.postman_collection.json` | Postman requests for every REST route, with basic checks |
| `HANDOVER.md` | This guide |

## 2. Server requirements

- **Java:** 17 or later (`java -version`). It was built and tested with Temurin 17.0.20.
- **Network:**
  - outbound HTTPS (TCP 443) from this server to the PVWA host
  - the PostgreSQL host and port
  - for use case 1 only, the CyberArk Identity tenant
  - for use case 2 only, the Identity tenant (token) and the `uap` or `sca` policy host
- **PostgreSQL user:** must be able to create the schema (or use an existing one) and own its tables, because the
  service creates and extends them (see §8).

## 3. Install

```bash
sudo mkdir -p /opt/keyforge-cyberark && cd /opt/keyforge-cyberark
# copy cyberark-extract.jar, cyberark-extract.env.example and run-extractions.sh here
cp cyberark-extract.env.example cyberark-extract.env
chmod 600 cyberark-extract.env
chmod 750 run-extractions.sh
```

Then edit `cyberark-extract.env`:
- **From the client:** the PVWA URL, the service account and its logon method.
- **From your side:** the PostgreSQL settings, and a REST username and password of your choice.

Values with special characters go in single quotes. Never commit the filled-in file or send it by chat or e-mail.

## 4. Certificate trust (only if PVWA uses the client's internal CA)

Java trusts the public certificate authorities in its default `cacerts`. A PVWA with a certificate from the
client's own CA fails with `error_kind: TRANSPORT` and "PKIX path building failed". The fix is a truststore that
holds Java's default authorities **plus** the client's CA:

```bash
# 1. Get the client's CA certificate (PEM) from the client; save it as client-ca.pem.
# 2. Start from Java's default truststore, so public CAs keep working:
cp "$JAVA_HOME/lib/security/cacerts" /opt/keyforge-cyberark/client-truststore.p12
# 3. Add the client's CA (the default cacerts password is 'changeit'; change it with keytool -storepasswd if wanted):
keytool -importcert -alias client-ca -file client-ca.pem \
  -keystore /opt/keyforge-cyberark/client-truststore.p12 -storepass changeit -noprompt
```

In `cyberark-extract.env`, set:
```bash
JAVA_TRUSTSTORE=/opt/keyforge-cyberark/client-truststore.p12
JAVA_TRUSTSTORE_PASSWORD=changeit
```

`run-extractions.sh` then passes `-Djavax.net.ssl.trustStore=…` to Java. To run the jar by hand, add
`-Djavax.net.ssl.trustStore=/opt/keyforge-cyberark/client-truststore.p12 -Djavax.net.ssl.trustStorePassword=changeit
-Djavax.net.ssl.trustStoreType=PKCS12`.

**Checked locally:** against an HTTPS test server with a self-made certificate, `pvwa-verify` gave
`FAILED / TRANSPORT / PKIX path building failed` without this truststore, and `SUCCESS` with it.

**Hostname:** the certificate must also match the host name in `CYBERARK_PVWA_BASE_URL`. Validation is never switched
off.

## 5. First run (in this order)

Load the settings, then start with the health check:
```bash
cd /opt/keyforge-cyberark
set -a; . ./cyberark-extract.env; set +a
java -jar cyberark-extract.jar pvwa-verify
```

**Expected:** `"status" : "SUCCESS"`, the vault's `ServerName`, `"logons" : 1`, `"logoff" : "ok"`, exit code 0. If it
fails, see §10 before going further.

Then all extractions:
```bash
./run-extractions.sh
```

It prints one line per command (`pvwa-safes exit=0 log=logs/…`) and stops if the health check fails.

**Each log is the run's JSON summary:**
- `status`, `extracted`, `inserted`, `updated`, `failed`, `pages`, `reported_total`, `complete`, `notes`
- `schema_changes`: the columns created or widened in this run
- `logons`, `logoff`

**Exit codes:**

| Code | Status |
|---|---|
| 0 | SUCCESS |
| 6 | COMPLETED_WITH_FAILURES (some records failed to store) |
| 7 | INCOMPLETE (CyberArk's reported total didn't match the records received, or paging stalled) |
| 2 | configuration error |
| 1 | FAILED |

**One command at a time:** e.g. `java -jar cyberark-extract.jar pvwa-safes`.

| Command | CyberArk call | Table |
|---|---|---|
| `pvwa-verify` | `GET /WebServices/PIMServices.svc/Verify/` (health check) | none |
| `pvwa-safes` | `GET /API/Safes/` (all pages) | `pvwa_safe` |
| `pvwa-accounts` | `GET /API/Accounts` (all pages; secrets removed) | `pvwa_account` |
| `pvwa-safe-members` | `GET /API/Safes/{SafeUrlId}/Members/` for every safe | `pvwa_safe_member` |
| `pvwa-target-platforms` | `GET /API/platforms/targets/` | `pvwa_target_platform` |
| `pvwa-platform-details` | `GET /API/Platforms/{PlatformID}/` for every platform | `pvwa_platform_detail` |
| `pvwa-users` | `GET /API/Users/?ExtendedDetails=true` (all pages) | `pvwa_user` |
| `pvwa-user-groups` | `GET /API/UserGroups/?includeMembers=true` (all pages) | `pvwa_user_group` |
| `pvwa-discovered-accounts` | `GET /API/DiscoveredAccounts/` (all pages; pending accounts only) | `pvwa_discovered_account` |

**Daily schedule** (cron; adjust the time):
```
0 2 * * * /opt/keyforge-cyberark/run-extractions.sh >> /opt/keyforge-cyberark/logs/cron.log 2>&1
```

## 6. REST service and Postman

```bash
set -a; . ./cyberark-extract.env; set +a
java -jar cyberark-extract.jar start-rest
```

**Startup:** it listens on `http://127.0.0.1:8210/cyberark-extract` (change with `REST_HOST` / `REST_PORT`).

**Security:**
- Every request needs HTTP Basic Auth with `REST_USERNAME` / `REST_PASSWORD`.
- Only one extraction runs at a time; a second one meanwhile gets HTTP 409.
- The service is plain HTTP, so only open it beyond `127.0.0.1` on a trusted network.

**Postman:**
1. Import `CyberArk-Extraction.postman_collection.json`.
2. Set the collection variables `baseUrl`, `restUsername` and `restPassword`.
3. Run the requests. Each checks for HTTP 200, `status: SUCCESS`, and no `"secret"` in the response.

**From the command line:**
```bash
postman collection run CyberArk-Extraction.postman_collection.json \
  --env-var baseUrl=http://127.0.0.1:8210/cyberark-extract --env-var restUsername=<user> --env-var restPassword=<password>
```

**HTTP status:**

| HTTP | Meaning |
|---|---|
| 200 | SUCCESS, COMPLETED_WITH_FAILURES or INCOMPLETE (see `status` and the `X-KF-Run-Status` header) |
| 500 | configuration error |
| 502 | a CyberArk or database failure |
| 401 | wrong Basic Auth |

## 7. Permissions to request

**PVWA service account** (one dedicated user, e.g. `svc-keyforge-readonly`):

| Needed for | Permission (from the official API pages) |
|---|---|
| Logon | Logon method CyberArk, LDAP or RADIUS. **No interactive MFA** on API logon: a RADIUS challenge can't be answered by a script |
| Safes | **Membership of every in-scope safe.** "Get all Safes" only returns the safes the user is a member of |
| Accounts | **List Accounts** in each safe |
| Safe members | **View Safe Members** in each safe |
| Users, User groups | Vault authorization **Audit users**. The request document says this is only needed for activity data, but the official "Get users" and "Get groups" pages require it. Users and groups above the account in the Vault hierarchy are not returned |
| Discovered accounts | Membership of **Vault Admins or PVWAAccountsFeedAdmins**. That's more than read-only, so the client may decline; then only this one extraction fails with a 403 |
| Target platforms, Platform details | Not stated on the official pages. Confirm on the first run |

**Must NOT be granted:** Retrieve accounts, Use accounts, Add / Update / Delete / Manage, or any right that can read,
change or use a secret.

**Other access:**
- **PostgreSQL user:** `CREATE` on the database (or on an existing schema set in `PG_DEST_SCHEMA`), and ownership of the
  tables it creates. It adds columns when CyberArk returns a new field.
- **Network:** this server to the PVWA host on TCP 443. Ask whether a load balancer or WAF needs the source IP
  allow-listed.

## 8. What the tables look like

- **Columns come from the data:** each table has one column per field CyberArk actually returns, under exactly the
  same name and letter case (e.g. `"safeName"`). Nested objects and arrays are `jsonb`. A field that only the client's
  PVWA version sends is stored as well.
- **Types:**
  - They follow the values: `boolean`, `bigint`, `numeric`, `text`, `jsonb`.
  - If values of a field disagree, the column is widened (e.g. number + text gives `text`) instead of a record being
    rejected.
  - A column first seen with only nulls is `text` until real values arrive.
- **Service columns:**
  - `record_uuid`: random, kept on re-runs.
  - `extracted_at`: when the record was last fetched.
- **Key:** CyberArk's own id (`safeUrlId`, `id`, `PlatformID`, or `safeUrlId` + `memberId` for members) has a unique
  index, so each run updates existing rows and never duplicates them.
- **Missing values:** a field that disappears from CyberArk is cleared, and a missing field and `null` are both SQL
  `NULL`.
- **Secrets:** fields named `secret` or `password` (any letter case, at any depth) are removed before anything is
  stored or returned.

Every run's `schema_changes` lists the columns added or widened. On the first real run this shows exactly what the
client's PVWA returns.

Example queries (schema `cyberark`):
```sql
SELECT column_name, data_type FROM information_schema.columns
WHERE table_schema = 'cyberark' AND table_name = 'pvwa_account' ORDER BY ordinal_position;

SELECT "id", "userName", "safeName", "secretManagement"->>'status' FROM cyberark.pvwa_account LIMIT 10;
```

## 9. Use case 1 (approver groups), optional

`java -jar cyberark-extract.jar ispss-approver-groups`, or `GET /cyberark-extract/ispss/approver-groups`. It checks
that every role matching `APP-CYA-ISPSS-SCA-AWS-%-BUApprovers` has at least 3 direct members and 3 verified active
users, with the result `PASS` / `FAIL` / `CANNOT_VERIFY` / `CHECK_FAILED` per role.

**Separate login:** it uses the CyberArk Identity login (`CYBERARK_IDENTITY_BASE_URL`, `CYBERARK_CLIENT_ID`,
`CYBERARK_CLIENT_SECRET`), not the PVWA one.

**Tables:** `ispss_role`, `ispss_role_member`, `ispss_user`, `ispss_approver_group_result`.

**Needs client confirmation first:** the Identity host, whether the platform token is accepted, and the service user's
rights (see the project's `docs/API_CONTRACT.md`).

## 9a. Use case 2 (policy health), optional

`java -jar cyberark-extract.jar ispss-policy-health`, or `GET /cyberark-extract/ispss/policy-health`. It reads every
SCA/SIA access policy and gives each one an outcome:

| Outcome | When |
|---|---|
| `FINDING` | the documented status is **Error** or **Warning**; `status_code` and `status_description` say why |
| `NO_FINDING` | another documented status (Active, Suspended, Expired, Validating) |
| `CANNOT_VERIFY` | the status is missing or not a documented value |

**Which API:** `CYBERARK_POLICY_API=uap` (default) calls the Access Control Policies API
(`https://<subdomain>.uap.cyberark.cloud/api/policies`, paged with `nextToken`, status as text).
`CYBERARK_POLICY_API=sca` calls the SCA Policies API (`https://<subdomain>.sca.cyberark.cloud/api/policies`, numeric
status: 4 = Error, 5 = Warning). The official UAP reference says tenants whose policies show on SCA's Policies page must
use the SCA API, so the client must say which one applies.

**Separate login:** the policy APIs need the **custom OAuth2 token**: `POST <identity>/oauth2/token/<app_id>` with the
service user as HTTP Basic auth. The platform token is never used here. The client has to create the custom OAuth2
server web app (Manage > Inventory > Targets > Applications > Add Web Apps > OAuth2 Server). That means:
- **Tokens tab:** Client Creds enabled.
- **Scope tab:** `full` or `sca`.
- **Permissions tab:** a read-only role, e.g. **SCAApiReadOnly**, or a custom role that contains it.
- **Advanced tab:** the documented claims script.

Then send us its Application ID.

**The run answer:**
- **`status`** describes the retrieval:
  - `FAILED`: nothing is stored or concluded.
  - `INCOMPLETE`: stored, but the list may be partial. Causes: a repeated `nextToken`, a `total` that doesn't match,
    no `total`, or a non-empty `failedServices`.
  - `COMPLETED_WITH_FAILURES`: a policy could not be stored, e.g. one without an id.
  - `SUCCESS`.
- **`health`** is the conclusion:
  - `FINDINGS`: at least one policy has a finding.
  - `ALL_HEALTHY`: only after a **complete** retrieval where every policy has a documented, healthy status.
  - `UNDETERMINED`: anything else.

  A failed or incomplete retrieval is never reported as all healthy. Exit codes follow `status`, as for the extractions.

**Tables:**
- `uap_policy`: every policy as returned. Columns come from the data, so nested objects such as `metadata` are `jsonb`.
  Two columns are ours: `policy_id` (the unique key) and `policy_api`.
- `uap_policy_health_result`: the latest outcome per `policy_id`, with `retrieval_complete`.

```sql
SELECT policy_id, policy_name, outcome, status, status_code, status_description, reason, retrieval_complete, extracted_at
FROM cyberark.uap_policy_health_result ORDER BY outcome, policy_name;
```

A policy deleted in CyberArk keeps its last row (see `extracted_at`).

## 10. Troubleshooting

| `error_kind` / symptom | Likely cause |
|---|---|
| `CONFIG_ERROR` (exit 2) | a required setting is missing or invalid; the message names it |
| `TRANSPORT` + "PKIX path building failed" | the client's certificate authority isn't trusted (see §4) |
| `TRANSPORT` + timeout / connection refused | firewall, wrong host or port, PVWA down |
| `AUTHENTICATION`, HTTP 401 on `logon` | wrong username, password or logon method, or MFA on the account |
| `AUTHENTICATION`, HTTP 403 on an endpoint | the account lacks that endpoint's permission (see §7) |
| `AUTHENTICATION` on `policy-token` | wrong policy service user or password, or the OAuth2 app does not allow Client Creds (see §9a) |
| `HTTP_STATUS` 404 on `policy-token` | wrong `CYBERARK_POLICY_APP_ID` |
| `AUTHENTICATION` on `policies` | the custom OAuth2 app lacks the SCA role or scope, or the wrong policy API is set (see §9a) |
| `HTTP_STATUS` 404 on `pvwa-verify` | this PVWA version uses another health-check path (see §11, item 1). The extractions can still work |
| `DATABASE` | PostgreSQL unreachable, wrong credentials, or no right to create or alter the tables |
| `INCOMPLETE` (exit 7) | CyberArk's total didn't match the records received, or paging stalled; the reason is in `notes` |
| `COMPLETED_WITH_FAILURES` (exit 6) | some records couldn't be stored; the first reason is in `error` |

Error messages never contain the vault password, session tokens, or secret values.

## 11. Open points that only the client's environment can settle

1. **PVWA version and health check:** the request document's `/API/Server/Verify` isn't in the official docs. The
   service uses the documented `/WebServices/PIMServices.svc/Verify/`. Newer versions may differ.
2. **Self-hosted or Privilege Cloud:** this login method is for self-hosted PVWA. Privilege Cloud uses a different
   (token-based) login.
3. **The CA certificate chain** (see §4), and whether a load balancer or WAF is in front.
4. **The real field names, types and totals:**
   - whether `count` / `Total` mean the overall total
   - whether `MaxDisplayedRecords` caps accounts
   - the casing of the platform fields
   - the time formats

   The service stores whatever arrives; `schema_changes` and `notes` show the details.
5. **The permissions in §7**, especially Audit users and PVWAAccountsFeedAdmins.
6. **A non-production PVWA** for the first run, if one exists.
7. **Use case 2:** whether the tenant uses the Access Control Policies API (`uap`) or the SCA Policies API (`sca`);
   the custom OAuth2 app's Application ID, scope and role; whether `total` counts all policies the token can see. The
   SCA reference documents no paging, so a tenant with more policies than one response returns would show as
   `INCOMPLETE`.
8. **PostgreSQL over TLS:** the service has no setting for an SSL-only database yet. Tell us if the target database
   requires it.
