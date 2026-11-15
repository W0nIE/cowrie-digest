# 07-auth-realism — realistic Cowrie authentication

Replaces the wildcard userdb (`user:x:*` — every password succeeds) with a
persona-driven **"Weak-Enterprise"** password set for the `srv04` fake web
server. Goals:

- Filter out Mirai-tier botnet noise (default creds must FAIL)
- Stay vulnerable to targeted wordlists/rules (year+symbol, leetspeak,
  host-derived passwords) → 1–3 high-value sessions/week instead of
  ~900 garbage logins/day
- Zero trivial fingerprinting (an attacker noticing "every password works"
  instantly identifies the honeypot)

## Auth strategy

| Tier | Users | Password style | Who it catches |
|------|-------|----------------|----------------|
| Root | `root` | keyboard walks + year, leetspeak host theme, `/^[Rr]oot[!@]2026$/` | targeted SSH brute-forcers |
| Deploy | `deploy` (uid 1000) | leetspeak role+year, `/^[Dd]eploy[#!]2026$/` | web-focused attackers, the persona's primary bait |
| Personal | `alex` (uid 1001) | name leetspeak, season+year | manual intruders following the persona |
| Trap | `admin` (uid 1002) | host-derived (`Manager@srv04` style), `/^[Aa]dmin2026!$/` | manual enumeration (admin is tried constantly) |

Design rules (enforced by `test.sh`):

1. **No `*` wildcards, no empty passwords, no top-10 trivia** — bot noise must fail.
2. Every accepted password has **< 5 hits/day** in historical `cowrie.json`
   (keeps success rate at the 1–3/week target).
3. Every userdb user must exist in the fake filesystem's `/etc/passwd`
   (in our deployment: `fs.pickle`, **not** honeyfs) with a matching home
   directory — attackers must never see `I have no name!@srv04`.
4. **Never commit the deployed userdb.** `userdb.txt` is gitignored;
   `userdb.txt.example` ships public placeholder credentials. Any password
   published in an issue/PR is burned — treat it as a decoy and deploy
   different ones.

## Files

```
userdb.txt.example   # public template — customize before deploy!
install.sh           # backup old userdb → deploy new → auth_class=UserDB → pickle admin sync → restart
uninstall.sh         # restore newest backup userdb (+ pre-module pickle) → restart
add_admin_user.py    # idempotent: adds admin (uid 1002) + /home/admin to fs.pickle
test.sh              # static audit, UID sync, regex validation, live E2E, log check
```

## Deploy

```bash
cp userdb.txt.example userdb.txt
$EDITOR userdb.txt          # invent YOUR OWN Weak-Enterprise passwords
sudo ./install.sh
sudo /opt/cowrie/ops/07-auth-realism/test.sh
```

Deployed layout:

```
/opt/cowrie/etc/userdb.txt                  # root:999 0640 (cowrie reads as UID 999)
/opt/cowrie/ops/07-auth-realism/
├── backups/    # timestamped userdb backups
├── log/
└── test.sh / uninstall.sh / add_admin_user.py
```

## Calibration

Watch the daily digest (module 01):

- **Too many successful logins (>10/day)?** Your accepted passwords are too
  common — re-check `cowrie.json` for which cred is being hit and make it
  rarer (longer base word, less obvious symbol placement).
- **Zero successful logins for weeks?** Add one credential that real
  attackers actually try (pick a mid-frequency one from `cowrie.login.failed`
  stats — e.g. a `word+year+!` shape that appears in your own logs).

## Cowrie internals (verified against cowrie/cowrie latest image)

- userdb line format: `login:x:password` — **field 2 is ignored** (see
  `cowrie/core/auth.py` `UserDB.load()`)
- Password rules: exact string, `*` (wildcard — forbidden here), or
  `/regex/` with optional `i` flag; matched via `re.search` — **anchor with
  `^...$` yourself**
- `!` prefix on a password = explicit deny rule (first match wins, in order)
- Auth class: `[honeypot] auth_class = UserDB` (fallback default; set
  explicitly by install.sh). `AuthRandom` exists (`auth_class_parameters =
  min,max,cache`) but is intentionally not used.
