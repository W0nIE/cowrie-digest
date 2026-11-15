# cowrie-digest

Daily attack digest + instant alerts for [Cowrie](https://github.com/cowrie/cowrie)
SSH/Telnet honeypots. Zero dependencies (Python 3 stdlib only), delivers via
**ntfy.sh** or **Telegram**.

Part of the `honeypot-ops` module family — self-contained: install, test,
uninstall without touching anything else on the system.

## What you get

- **Daily digest** (cron, 09:00) — connections, unique attacker IPs, failed/successful
  logins, top credentials tried, top commands executed, malware download URLs,
  and the list of IPs that got a shell.
- **Instant alerts** (cron, every 5 min) — one **consolidated** message per run
  covering new events, so a bot storm can't flood your phone:
  - `cowrie.login.success` — someone got into the fake shell (count + top creds/IPs)
  - `cowrie.session.file_download` — malware captured (URL + SHA256)

  Alert runs scan at most the last 10 MB of the log, so a multi-GB
  `cowrie.json` never slows the 5-minute cron down.

Example digest:

```
🍯 Cowrie digest [srv04] — last 24h

Connections:       312
Unique IPs:        47
Failed logins:     1042
Successful logins: 6
Commands run:      89
Files downloaded:  2

Top attacker IPs:
     58x  103.38.219.22
     41x  45.148.10.87
...
```

## Requirements

- A running Cowrie honeypot with JSON logging enabled (`cowrie.json`)
- Python 3.8+
- Root (for cron installation)

## Quick start

```bash
git clone https://github.com/<you>/cowrie-digest.git
cd cowrie-digest
sudo ./install.sh
sudoedit /opt/cowrie/ops/01-digest/config.env   # pick channel + topic/token
sudo /opt/cowrie/ops/01-digest/digest.py --print   # preview report, sends nothing
sudo /opt/cowrie/ops/01-digest/digest.py --digest  # send real report now
```

## Configuration

All settings live in `/opt/cowrie/ops/01-digest/config.env`
(created from [`config.env.example`](config.env.example) on install, mode 0600).

| Variable | Meaning |
|---|---|
| `CHANNEL` | `ntfy` or `telegram` |
| `NTFY_TOPIC` | ntfy.sh topic name — make it long and unguessable |
| `NTFY_SERVER` | ntfy server (default `https://ntfy.sh`, self-hostable) |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | from @BotFather / @userinfobot |
| `COWRIE_LOG` | path to `cowrie.json` |
| `DIGEST_HOURS` | hours covered by the daily report (default 24) |
| `SENSOR_NAME` | label in reports — handy with multiple honeypots |

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for step-by-step channel setup.

## How it works

```
/etc/cron.d/cowrie-digest
├── 0 9 * * *    digest.py --digest   → aggregate last 24h → send report
└── */5 * * * *  digest.py --alerts   → new success/download events → send alert
```

`--alerts` keeps a timestamp marker in `state/last_alert.ts`, so every event
is reported exactly once, even across restarts.

## Testing

```bash
./test.sh
```

Runs the digest against `tests/fixtures/sample_cowrie.jsonl` (a fabricated
attack log) and asserts every aggregation — no Cowrie, no network needed.

## Uninstall

```bash
sudo /opt/cowrie/ops/01-digest/uninstall.sh   # or: sudo ./uninstall.sh before deleting
```

Removes the cron file and the module directory. Cowrie itself and other
modules are untouched.

## Layout after install

```
/opt/cowrie/ops/01-digest/
├── digest.py       # the tool
├── config.env      # your secrets (0600)
├── state/          # alert timestamps
└── log/            # cron output logs
```

## License

MIT — see [LICENSE](LICENSE).
