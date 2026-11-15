# Pseudonymization (compliance layer)

All outbound reports (ntfy, any future channel) replace attacker IPv4
addresses with stable pseudonyms: `109.160.32.136` → `ip-9f4a2c81e7b3`.

## How it works

```
pseudonym = "ip-" + HMAC_SHA256(key, "ip:" + address)[:12 hex]
```

- **Keyed** — without the secret key, nobody can reverse a pseudonym, even
  by brute-forcing the whole IPv4 space (unlike plain SHA256).
- **Deterministic** — the same IP always maps to the same pseudonym, so
  top-attacker tables and counts stay meaningful across reports.
- **Perimeter rule** — the key never leaves the server. Raw IPs exist only
  in `cowrie.json`.

## The key

| | |
|---|---|
| Location | `/opt/cowrie/ops/secrets/pseudo.key` |
| Format | 32 random bytes, hex-encoded, one line |
| Permissions | `root:root 0600` |
| Created by | `install.sh` (only if absent — existing keys are kept) |
| Git | **never** (gitignored) |

## Config (`config.env`)

```bash
PSEUDO_ENABLED=true                                  # keep ON
PSEUDO_KEY_PATH=/opt/cowrie/ops/secrets/pseudo.key
```

If delivery is requested but the key is missing/broken, the module **refuses
to send** — no message is better than raw IPs leaving the server.

## Reverse lookup (on the server only)

"Which real IP is `ip-9f4a2c81e7b3`?"

```bash
sudo python3 - <<'EOF'
import json, sys
sys.path.insert(0, "/opt/cowrie/ops/01-digest")
from pathlib import Path
from lib.pseudo import Pseudonymizer, load_key

target = "ip-9f4a2c81e7b3"
p = Pseudonymizer(load_key(Path("/opt/cowrie/ops/secrets/pseudo.key")))
seen = set()
for line in open("/opt/cowrie/var/log/cowrie/cowrie.json"):
    try:
        ip = json.loads(line).get("src_ip")
    except ValueError:
        continue
    if ip and ip not in seen:
        seen.add(ip)
        if p.pseudo_ip(ip) == target:
            print("MATCH:", ip)
            break
else:
    print("no match in current log")
EOF
```

## Key rotation

Rotating the key changes **all** pseudonyms (old reports stop matching new
ones — historical correlation is lost, which is sometimes exactly what you
want):

```bash
sudo rm /opt/cowrie/ops/secrets/pseudo.key
sudo /opt/cowrie/ops/src/cowrie-digest/install.sh   # regenerates
```

Do it when: the key may have leaked, or you want to break linkability of
older reports (privacy-by-design).

## Local debugging

```bash
digest.py --print        # pseudonymized (safe to copy-paste anywhere)
digest.py --print-raw    # RAW IPs — local debugging only, never sends
```
