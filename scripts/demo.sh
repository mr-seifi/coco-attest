#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

GO="${GO:-go}"
GORUN_LDFLAGS="${GORUN_LDFLAGS:--ldflags=-linkmode=external}"
run() { CGO_ENABLED=1 $GO run $GORUN_LDFLAGS "$@"; }

KBS_URL="http://127.0.0.1:8080"
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

echo "==> sealing demo config"
run ./cmd/seal -in config.plain.txt -out config.sealed.bin

echo "==> starting KBS"
run ./cmd/kbs >/tmp/poc-kbs.log 2>&1 & pids+=($!)
for i in $(seq 1 30); do curl -sf "$KBS_URL/healthz" >/dev/null && break; sleep 0.5; done
echo "    KBS healthy"

echo "==> starting workload (attests, unseals, serves)"
WORKLOAD_ADDR=:9090 KBS_URL="$KBS_URL" SEALED_CONFIG=config.sealed.bin \
  run ./cmd/workload >/tmp/poc-workload.log 2>&1 & pids+=($!)
for i in $(seq 1 40); do curl -sf localhost:9090/healthz >/dev/null && break; sleep 0.5; done

echo
echo "---- GET /config (only readable after attested key release) ----"
curl -s localhost:9090/config
echo "---- GET /sign?msg=hello (HMAC with released key, key never leaves) ----"
curl -s "localhost:9090/sign?msg=hello"

echo
echo "==> tamper case: workload with an UNTRUSTED launch measurement"
set +e
WORKLOAD_ADDR=:9091 KBS_URL="$KBS_URL" SEALED_CONFIG=config.sealed.bin \
  WORKLOAD_LAUNCH_DIGEST="tampered-image:evil" \
  timeout 12 bash -c "CGO_ENABLED=1 $GO run $GORUN_LDFLAGS ./cmd/workload" 2>&1 \
  | grep -v LC_UUID | tail -1
code=${PIPESTATUS[0]}
set -e
echo "    tampered workload exit code: $code (non-zero == refused to serve, as intended)"
echo
echo "Demo complete."
