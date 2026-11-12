#!/usr/bin/env bash
# Runs the PVWA extractions once, in order, with the settings in cyberark-extract.env.
#
#   ./run-extractions.sh                  all 8 PVWA extractions (after the Verify health check)
#   ./run-extractions.sh pvwa-safes ...   only the commands given
#
# Each command's JSON summary goes to logs/<command>-<timestamp>.log. Exit code: 0 when every command
# succeeded, otherwise the first non-zero exit code (6 COMPLETED_WITH_FAILURES, 7 INCOMPLETE, 2 configuration,
# 1 FAILED). If the Verify health check fails, nothing else is run.
set -u
cd "$(dirname "$0")"

ENV_FILE="${ENV_FILE:-./cyberark-extract.env}"
JAR="${JAR:-./cyberark-extract.jar}"
if [ ! -r "$ENV_FILE" ]; then
  echo "Settings file $ENV_FILE not found (copy cyberark-extract.env.example and fill it in)." >&2
  exit 2
fi
set -a
. "$ENV_FILE"
set +a

# Optional: trust the client's internal certificate authority (see HANDOVER.md, "Certificate trust").
JAVA_OPTS=()
if [ -n "${JAVA_TRUSTSTORE:-}" ]; then
  JAVA_OPTS+=("-Djavax.net.ssl.trustStore=${JAVA_TRUSTSTORE}" "-Djavax.net.ssl.trustStoreType=PKCS12")
  if [ -n "${JAVA_TRUSTSTORE_PASSWORD:-}" ]; then
    JAVA_OPTS+=("-Djavax.net.ssl.trustStorePassword=${JAVA_TRUSTSTORE_PASSWORD}")
  fi
fi
# Extra JVM options, e.g. for a local Windows test (-Djdk.net.unixdomain.tmpdir=...). Not needed on Linux.
if [ -n "${EXTRA_JAVA_OPTS:-}" ]; then
  read -r -a extra <<< "$EXTRA_JAVA_OPTS"
  JAVA_OPTS+=("${extra[@]}")
fi

if [ "$#" -gt 0 ]; then
  COMMANDS=("$@")
else
  COMMANDS=(pvwa-verify pvwa-safes pvwa-accounts pvwa-safe-members pvwa-target-platforms pvwa-platform-details
            pvwa-users pvwa-user-groups pvwa-discovered-accounts)
fi

mkdir -p logs
first_failure=0
for cmd in "${COMMANDS[@]}"; do
  log="logs/${cmd}-$(date +%Y%m%d-%H%M%S).log"
  # ${A[@]+"${A[@]}"} keeps an empty array working under set -u on bash 4.2 (e.g. RHEL 7).
  java ${JAVA_OPTS[@]+"${JAVA_OPTS[@]}"} -jar "$JAR" "$cmd" > "$log" 2>&1
  code=$?
  echo "$(date '+%Y-%m-%d %H:%M:%S') ${cmd} exit=${code} log=${log}"
  if [ "$code" -ne 0 ] && [ "$first_failure" -eq 0 ]; then
    first_failure=$code
  fi
  if [ "$cmd" = "pvwa-verify" ] && [ "$code" -ne 0 ]; then
    echo "The Verify health check failed; nothing else was run. See ${log}." >&2
    exit "$code"
  fi
done
exit "$first_failure"
