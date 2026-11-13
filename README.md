# CyberArk Integration

A Java service that calls the CyberArk APIs and returns their data as JSON. You can call it from the command
line or over REST.

## What it does

| Service | CLI command | REST route (`GET`) | CyberArk call |
|---|---|---|---|
| Login test | `cloud-token` | `/cyberark-extract/cloud/token` | OAuth2 token |
| Redrock query | `cloud-redrock` | `/cyberark-extract/cloud/redrock` | `POST /Redrock/query` (one page) |
| Role details | `cloud-role` | `/cyberark-extract/cloud/role` | `POST /Roles/GetRole` |
| Policies | `cloud-policies` | `/cyberark-extract/cloud/policies` | `GET /policies` (one page) |
| PVWA data | `pvwa-safes`, `pvwa-accounts`, `pvwa-users`, … | `/cyberark-extract/pvwa/...` | PVWA REST API, stored in PostgreSQL |
| Approver groups check | `ispss-approver-groups` | `/cyberark-extract/ispss/approver-groups` | Redrock + Roles |
| Policy health check | `ispss-policy-health` | `/cyberark-extract/ispss/policy-health` | Policies |

**How it works:**
1. It reads the CyberArk URLs and credentials from environment variables.
2. It gets an OAuth2 token.
3. It makes the request and returns CyberArk's answer unchanged.

Each call makes one request to CyberArk. To get the next page, call again with the `next_request` values from the
response.

## Response

Every call returns one JSON object:

```json
{
  "route": "cloud/redrock",
  "status": "SUCCESS",
  "ok": true,
  "request": { "method": "POST", "url": "https://<tenant>/api/Redrock/query", "body": { "...": "..." } },
  "http_status": 200,
  "response": { "...": "CyberArk's response, unchanged" },
  "completeness": {
    "response_complete": true,
    "records_in_response": 2,
    "more_available": null,
    "next_request": { "pageNumber": 2, "pageSize": 2 },
    "basis": "full page (2 rows): more rows may exist..."
  },
  "duration_ms": 76
}
```

- `response` is exactly what CyberArk returned.
- **Response size:**
  - There is no size cap by default.
  - Responses up to 1 MB are kept in memory. Larger ones are streamed to a temporary file in the spool directory
    (`CYBERARK_SPOOL_DIR`, by default `<system temp>/cyberark-poc-responses`) and deleted once sent.
  - `CYBERARK_SPOOL_MIN_FREE_MB` (default 512) is the free space that must stay on the spool disk. A response that
    would go below it fails with `LOCAL_LIMIT`.
  - `CYBERARK_MAX_RESPONSE_MB` is an optional cap (off by default). A larger response fails with `LOCAL_LIMIT`.
  - Neither of these is a CyberArk limit, and a part of a response is never returned.
- `completeness` says whether this page is complete, whether more pages exist, and what to send to get the next one.
- When a call fails, `status` is `FAILED` and `error_kind` says why: `AUTHENTICATION`, `AUTHORIZATION`,
  `RATE_LIMITED`, `HTTP_STATUS`, `API_FAILURE`, `INVALID_RESPONSE` or `TRANSPORT`. A wrong parameter gives
  `BAD_REQUEST`, and a missing setting gives `CONFIG_ERROR`.
- Secrets are never printed.

## Settings

| Variable | Meaning |
|---|---|
| `CYBERARK_IDENTITY_BASE_URL` | Identity API base, e.g. `https://<tenant>.id.cyberark.cloud` |
| `CYBERARK_TOKEN_URL` | optional; defaults to `<identity base>/oauth2/platformtoken` |
| `CYBERARK_CLIENT_ID`, `CYBERARK_CLIENT_SECRET` | service user credentials |
| `CYBERARK_UAP_BASE_URL` | Policies API base, e.g. `https://<sub>.uap.cyberark.cloud/api` |
| `CYBERARK_POLICY_TOKEN_URL` | token URL for the policy calls |
| `CYBERARK_PVWA_BASE_URL`, `CYBERARK_PVWA_USERNAME`, `CYBERARK_PVWA_PASSWORD` | PVWA (only for `pvwa-*`) |
| `PG_HOST`, `PG_PORT`, `PG_DATABASE`, `PG_USERNAME`, `PG_PASSWORD` | PostgreSQL (only for services that store data) |
| `REST_USERNAME`, `REST_PASSWORD`, `REST_PORT` | REST server Basic auth and port (default 8210) |

The full list, with comments, is in `deploy/cyberark-extract.env.example`.

## Build and run

Java 17 and Maven:

```bash
mvn package
```

```bash
java -jar target/cyberark-extract.jar cloud-redrock "script=SELECT ID, Name FROM Role" pageNumber=1 pageSize=100
```

```bash
java -jar target/cyberark-extract.jar cloud-role id=<role id>
```

```bash
java -jar target/cyberark-extract.jar cloud-policies limit=50
```

```bash
java -jar target/cyberark-extract.jar start-rest
```

Exit codes: `0` success, `1` the CyberArk call failed, `2` bad parameter or setting.

## Local testing

`target/cyberark-poc.jar` includes a mock CyberArk with made-up data:

```bash
java -jar target/cyberark-poc.jar mock 8300
```

Then point the settings at `http://127.0.0.1:8300/api`, with client id `mock-client` and secret `mock-secret`.
`mvn test` runs every test against the mock.
