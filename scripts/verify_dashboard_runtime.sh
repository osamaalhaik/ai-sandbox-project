#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:8010}"

paths=(
    "/"
    "/runs"
    "/alerts"
    "/approvals"
    "/reports/security-summary"
    "/project-overview"
    "/docs"
    "/api/stats"
    "/api/runs"
    "/api/gateway/decisions"
    "/api/gateway/pending"
    "/api/gateway/approvals"
    "/api/operations/runs?page=1&page_size=5"
    "/api/operations/alerts?page=1&page_size=5"
    "/api/operations/summary"
    "/api/reports/security-summary"
)

assets=(
    "/static/dashboard.css"
    "/static/dashboard.js"
    "/static/page-ui.js"
    "/static/table-enhancements.js"
    "/static/operations-tables.js"
    "/static/approval-workflow.js"
)

failures=0

for path in "${paths[@]}"; do
    status="$(curl -sS -o /tmp/procsentinel-runtime-response -w "%{http_code}" "${BASE_URL}${path}" || true)"

    printf "%-58s %s\n" "$path" "$status"

    if [ "$status" != "200" ]; then
        failures=$((failures + 1))
    fi
done

for path in "${assets[@]}"; do
    status="$(curl -sS -o /tmp/procsentinel-runtime-response -w "%{http_code}" "${BASE_URL}${path}" || true)"

    printf "%-58s %s\n" "$path" "$status"

    if [ "$status" != "200" ]; then
        failures=$((failures + 1))
    fi
done

rm -f /tmp/procsentinel-runtime-response

if [ "$failures" -ne 0 ]; then
    echo "RUNTIME_VALIDATION_FAILED=$failures"
    exit 1
fi

echo "RUNTIME_VALIDATION_OK"
