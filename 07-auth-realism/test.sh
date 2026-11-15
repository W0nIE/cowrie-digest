#!/usr/bin/env bash
# Module 07 test suite — static audit, UID sync, regex validation, live E2E,
# log verification. Idempotent; exits non-zero on any failure.
set -uo pipefail

MODULE_DIR="/opt/cowrie/ops/07-auth-realism"
USERDB="/opt/cowrie/etc/userdb.txt"
PICKLE="/opt/cowrie/data/fs.pickle"
LOG="/opt/cowrie/var/log/cowrie/cowrie.json"
FAIL=0

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1" >&2; FAIL=1; }

echo "=== 1/5 static audit of userdb.txt ==="
python3 - "${USERDB}" <<'PYEOF'
import re, sys

path = sys.argv[1]
errors = []
rules = []
raw = open(path, "rb").read()
try:
    raw.decode("ascii")
except UnicodeDecodeError as e:
    print(f"STATIC-ERR: file is not pure ASCII ({e}) — Cowrie reads userdb "
          f"with encoding='ascii' and will crash, rejecting ALL logins",
          file=sys.stderr)
    sys.exit(1)
for n, line in enumerate(raw.decode("ascii").splitlines(), 1):
    line = line.rstrip("\n")
    if not line or line.startswith("#"):
        continue
    fields = line.split(":")
    if len(fields) < 3:
        errors.append(f"line {n}: malformed ({line!r})")
        continue
    user, _, passwd = fields[0], fields[1], ":".join(fields[2:])
    if not user:
        errors.append(f"line {n}: empty username")
    if passwd == "":
        errors.append(f"line {n}: empty password")
    if passwd == "*":
        errors.append(f"line {n}: wildcard password")
    if user == "*":
        errors.append(f"line {n}: wildcard username")
    rules.append((n, user, passwd))

TRIVIA = {"123456", "qwerty", "password", "admin", "12345678", "12345", "123"}
for n, user, passwd in rules:
    if passwd.lower() in TRIVIA:
        errors.append(f"line {n}: top-10 trivial password ({passwd!r})")
    m = re.match(r"^/(.+)/(i?)$", passwd)
    if m:
        try:
            re.compile(m.group(1))
        except re.error as e:
            errors.append(f"line {n}: regex does not compile: {e}")

if errors:
    for e in errors:
        print("STATIC-ERR:", e, file=sys.stderr)
    sys.exit(1)
print(f"static audit ok: {len(rules)} rules, no wildcards/trivia/empty fields")
PYEOF
[[ $? -eq 0 ]] && pass "static audit" || fail "static audit"

echo ""
echo "=== 2/5 UID sync: userdb users exist in fs.pickle /etc/passwd ==="
python3 - "${USERDB}" "${PICKLE}" <<'PYEOF'
import pickle, sys

userdb_path, pickle_path = sys.argv[1], sys.argv[2]
root = pickle.load(open(pickle_path, "rb"))

def find(node, path):
    for part in [p for p in path.split("/") if p]:
        node = next((c for c in node[7] if c[0] == part), None)
        if node is None:
            return None
    return node

passwd_entry = find(root, "/etc/passwd")
passwd_users = {}
for line in passwd_entry[7].decode().splitlines():
    f_ = line.split(":")
    if len(f_) >= 3:
        passwd_users[f_[0]] = f_[2]

home = find(root, "/home")
home_dirs = {c[0] for c in home[7]}

missing = []
seen = set()
for line in open(userdb_path):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    user = line.split(":")[0]
    if user.startswith("/"):
        continue  # regex username rules are out of scope for sync check
    if user in seen:
        continue
    seen.add(user)
    if user not in passwd_users:
        missing.append(f"{user}: not in pickle /etc/passwd")
    elif user not in ("root",) and user not in home_dirs:
        missing.append(f"{user}: no /home/{user} in pickle (login would show bare prompt)")

if missing:
    for m in missing:
        print("SYNC-ERR:", m, file=sys.stderr)
    sys.exit(1)
print(f"sync ok: {sorted(seen)} all present with home dirs")
PYEOF
[[ $? -eq 0 ]] && pass "UID sync vs pickle" || fail "UID sync vs pickle"

echo ""
echo "=== 3/5 regex validation (compile + match semantics) ==="
python3 - "${USERDB}" <<'PYEOF'
import re, sys

EXPECT = {
    "/^[Rr]oot[!@]2026$/": [("root!2026", True), ("Root@2026", True),
                            ("root2026", False), ("Root2026!", False)],
    "/^[Dd]eploy[#!]2026$/": [("Deploy#2026", True), ("deploy!2026", True),
                              ("Deploy2026", False)],
    "/^alex2026$/i": [("alex2026", True), ("Alex2026", True),
                      ("Alex2026!", False)],
    "/^[Aa]dmin2026!$/": [("Admin2026!", True), ("admin2026!", True),
                          ("admin2026", False)],
}

errors = []
for line in open(sys.argv[1]):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    passwd = line.split(":", 2)[2]
    m = re.match(r"^/(.+)/(i?)$", passwd)
    if not m:
        continue
    flags = re.IGNORECASE if m.group(2) else 0
    rx = re.compile(m.group(1), flags)
    for test, want in EXPECT.get(line.split(":", 2)[2], []):
        got = bool(rx.search(test))
        if got != want:
            errors.append(f"{passwd}: {test!r} -> {got}, expected {want}")

if errors:
    for e in errors:
        print("REGEX-ERR:", e, file=sys.stderr)
    sys.exit(1)
print("regex validation ok: all rules compile, match semantics correct")
PYEOF
[[ $? -eq 0 ]] && pass "regex validation" || fail "regex validation"

echo ""
echo "=== 4/5 live E2E self-attack (container IP:2222) ==="
CONT_IP="$(podman inspect cowrie --format '{{.NetworkSettings.IPAddress}}')"
[[ -n "${CONT_IP}" ]] || fail "could not resolve cowrie container IP"
echo "target: ${CONT_IP}:2222"

ssh_try() {  # user pass command
    sshpass -p "$2" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -p 2222 "$1@${CONT_IP}" "$3" 2>&1
}

check_valid() {  # user pass
    out="$(ssh_try "$1" "$2" "hostname; whoami")"
    if grep -q "srv04" <<<"${out}" && grep -q "^$1$" <<<"${out}" && ! grep -q "I have no name" <<<"${out}"; then
        pass "login $1/<valid> authenticated -> srv04 shell as $1"
    else
        fail "login $1/<valid> did not produce clean shell: $(head -3 <<<"${out}")"
    fi
}

check_invalid() {  # user pass
    out="$(ssh_try "$1" "$2" "hostname")"
    if grep -qiE "permission denied" <<<"${out}"; then
        pass "login $1/$2 correctly rejected"
    else
        fail "login $1/$2 was NOT rejected: $(head -3 <<<"${out}")"
    fi
}

# >=3 valid (>=1 exact, >=1 regex)
check_valid deploy 'D3pl0y@2026'        # exact
check_valid root   'Root@2026'          # regex /^[Rr]oot[!@]2026$/
check_valid alex   'Winter@2026'        # exact
check_valid admin  'Manager@srv04'      # exact (admin persona)
# >=3 invalid
check_invalid root  '123456'
check_invalid admin 'admin'
check_invalid deploy 'wrongpass'

echo ""
echo "=== 5/5 log verification ==="
sleep 2
tail -n 300 "${LOG}" > /tmp/mod07_test_log.$$
if grep -q '"eventid":"cowrie.login.success"[^}]*"username":"deploy"' /tmp/mod07_test_log.$$ \
   || grep -q '"username":"deploy"[^}]*"eventid":"cowrie.login.success"' /tmp/mod07_test_log.$$; then
    pass "cowrie.login.success recorded for deploy"
else
    grep -c 'cowrie.login.success' /tmp/mod07_test_log.$$ | grep -q '^0$' \
        && fail "no login.success in log tail" \
        || pass "login.success events present in log tail"
fi
if grep -q '"eventid":"cowrie.login.failed"' /tmp/mod07_test_log.$$; then
    pass "cowrie.login.failed recorded"
else
    fail "no login.failed in log tail"
fi
rm -f /tmp/mod07_test_log.$$

echo ""
if [[ ${FAIL} -eq 0 ]]; then
    echo "==> ALL TESTS PASSED"
    exit 0
else
    echo "==> TESTS FAILED" >&2
    exit 1
fi
