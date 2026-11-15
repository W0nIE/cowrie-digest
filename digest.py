#!/usr/bin/env python3
"""cowrie-digest — daily digest and instant alerts from Cowrie honeypot logs.

Reads cowrie.json (JSON-lines), aggregates attack activity, and delivers
a compact report via Telegram or ntfy.sh.

Modes:
  --digest   Aggregate the last 24h and send a full report (run daily via cron)
  --alerts   Send instant alerts for high-value events since last run
             (successful logins, malware downloads) — run every 5 min via cron
  --print    Print the digest to stdout without sending (dry run)

Configuration: config.env next to this script (see config.env.example).
Pure Python 3 stdlib — no dependencies.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = SCRIPT_DIR / "config.env"
STATE_DIR_DEFAULT = SCRIPT_DIR / "state"
DEFAULT_KEY_PATH = "/opt/cowrie/ops/secrets/pseudo.key"

sys.path.insert(0, str(SCRIPT_DIR))
from lib.pseudo import Pseudonymizer, load_key  # noqa: E402


def pseudo_enabled(cfg: dict) -> bool:
    return cfg.get("PSEUDO_ENABLED", "true").lower() in ("1", "true", "yes")


def get_masker(cfg: dict, required: bool) -> Pseudonymizer | None:
    """Return the pseudonymizer, or None if disabled.

    required=True (any outbound delivery): a missing/broken key is a hard
    error — better no message than raw IPs leaving the server.
    required=False (local --print): fall back to raw with a warning.
    """
    if not pseudo_enabled(cfg):
        return None
    key_path = Path(cfg.get("PSEUDO_KEY_PATH", DEFAULT_KEY_PATH))
    try:
        return Pseudonymizer(load_key(key_path))
    except (OSError, ValueError) as exc:
        if required:
            raise RuntimeError(
                f"PSEUDO_ENABLED but key unusable ({exc}) — refusing to "
                f"deliver raw IPs. Run install.sh to generate the key.") from None
        print(f"warning: pseudonymization unavailable ({exc}), printing raw",
              file=sys.stderr)
        return None


# ------------------------------------------------------------------ config
def load_config(path: Path) -> dict:
    cfg = {}
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            cfg[key.strip()] = value.strip().strip('"').strip("'")
    cfg.setdefault("CHANNEL", "ntfy")
    cfg.setdefault("NTFY_SERVER", "https://ntfy.sh")
    cfg.setdefault("COWRIE_LOG", "/opt/cowrie/var/log/cowrie/cowrie.json")
    cfg.setdefault("STATE_DIR", str(STATE_DIR_DEFAULT))
    cfg.setdefault("SENSOR_NAME", "cowrie")
    cfg.setdefault("DIGEST_HOURS", "24")
    return cfg


# ------------------------------------------------------------------ parsing
def iter_events(log_path: Path, since: datetime, tail_bytes: int | None = None):
    """Yield event dicts parsed from JSON-lines cowrie log, newer than `since`.

    If `tail_bytes` is set and the file is larger, only the last `tail_bytes`
    are scanned (first partial line is skipped). This bounds CPU/IO when
    cowrie.json has grown large — alerts run every 5 minutes.
    """
    if not log_path.exists():
        return
    with log_path.open("r", encoding="utf-8", errors="replace") as fh:
        if tail_bytes is not None:
            fh.seek(0, 2)
            size = fh.tell()
            if size > tail_bytes:
                fh.seek(size - tail_bytes)
                fh.readline()  # discard partial line
            else:
                fh.seek(0)
        for line in fh:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts_raw = ev.get("timestamp")
            if not ts_raw:
                continue
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except ValueError:
                continue
            if ts >= since:
                ev["_ts"] = ts
                yield ev


def collect(log_path: Path, since: datetime) -> dict:
    stats = {
        "connections": 0,
        "unique_ips": set(),
        "failed_logins": 0,
        "success_logins": 0,
        "commands": 0,
        "downloads": 0,
        "top_ips": Counter(),
        "top_users": Counter(),
        "top_passwords": Counter(),
        "top_creds": Counter(),
        "top_commands": Counter(),
        "download_urls": [],
        "success_ips": set(),
        "clients": Counter(),
    }
    for ev in iter_events(log_path, since):
        eid = ev.get("eventid", "")
        src = ev.get("src_ip")
        if src:
            stats["unique_ips"].add(src)
        if eid == "cowrie.session.connect":
            stats["connections"] += 1
            if src:
                stats["top_ips"][src] += 1
        elif eid == "cowrie.client.version":
            version = ev.get("version", "")
            if version:
                stats["clients"][version] += 1
        elif eid in ("cowrie.login.failed", "cowrie.login.success"):
            user = ev.get("username", "")
            pw = ev.get("password", "")
            if eid == "cowrie.login.failed":
                stats["failed_logins"] += 1
            else:
                stats["success_logins"] += 1
                if src:
                    stats["success_ips"].add(src)
            if user:
                stats["top_users"][user] += 1
            if pw:
                stats["top_passwords"][pw] += 1
            if user or pw:
                stats["top_creds"][f"{user}/{pw}"] += 1
        elif eid == "cowrie.command.input":
            stats["commands"] += 1
            cmd = (ev.get("input") or "").strip()
            if cmd:
                stats["top_commands"][cmd] += 1
        elif eid == "cowrie.session.file_download":
            stats["downloads"] += 1
            url = ev.get("url", "")
            if url:
                stats["download_urls"].append(url)
    return stats


# ------------------------------------------------------------------ report
def fmt_table(rows, limit=10):
    lines = []
    for name, count in rows[:limit]:
        name = name if len(name) <= 60 else name[:57] + "..."
        lines.append(f"  {count:>5}x  {name}")
    return "\n".join(lines) if lines else "  (none)"


def build_digest(stats: dict, hours: int, sensor: str) -> str:
    parts = [
        f"🍯 Cowrie digest [{sensor}] — last {hours}h",
        "",
        f"Connections:      {stats['connections']}",
        f"Unique IPs:       {len(stats['unique_ips'])}",
        f"Failed logins:    {stats['failed_logins']}",
        f"Successful logins: {stats['success_logins']}",
        f"Commands run:     {stats['commands']}",
        f"Files downloaded: {stats['downloads']}",
    ]
    if stats["connections"]:
        parts += ["", "Top attacker IPs:", fmt_table(stats["top_ips"].most_common())]
    if stats["top_creds"]:
        parts += ["", "Top credentials tried:", fmt_table(stats["top_creds"].most_common())]
    if stats["top_commands"]:
        parts += ["", "Top commands:", fmt_table(stats["top_commands"].most_common(15))]
    if stats["download_urls"]:
        parts += ["", "Download URLs:"]
        parts += [f"  {u}" for u in stats["download_urls"][:10]]
    if stats["success_ips"]:
        parts += ["", "⚠️ IPs that got a shell:", ", ".join(sorted(stats["success_ips"]))]
    return "\n".join(parts)


def build_alert(ev: dict, sensor: str) -> str | None:
    """Single-event alert text (kept for --alerts dry debugging)."""
    eid = ev.get("eventid")
    src = ev.get("src_ip", "?")
    if eid == "cowrie.login.success":
        return (f"🚨 [{sensor}] Successful login from {src}: "
                f"{ev.get('username')}/{ev.get('password')}")
    if eid == "cowrie.session.file_download":
        return (f"🦠 [{sensor}] Malware download by {src}: "
                f"{ev.get('url', '?')} (sha256: {str(ev.get('shasum', '?'))[:12]}…)")
    return None


def build_alert_summary(successes: list, downloads: list, sensor: str,
                        sample_limit: int = 5) -> str:
    """One consolidated alert per run — NOT one message per event.

    With a permissive userdb every bot login "succeeds", so per-event alerts
    would flood the channel (self-inflicted DoS). Aggregate instead.
    """
    parts = [f"🚨 [{sensor}] Honeypot alert"]
    if successes:
        parts.append(f"\n✅ Successful logins: {len(successes)}")
        creds = Counter(f"{ip} → {u}/{p}" for ip, u, p in successes)
        for label, count in creds.most_common(sample_limit):
            parts.append(f"  {count}x  {label}")
        remaining = len(creds) - sample_limit
        if remaining > 0:
            parts.append(f"  …and {remaining} more credential pairs")
    if downloads:
        parts.append(f"\n🦠 Malware downloads: {len(downloads)}")
        for ip, url, shasum in downloads[:sample_limit]:
            parts.append(f"  {ip}: {url}")
            if shasum:
                parts.append(f"    sha256: {shasum}")
        remaining = len(downloads) - sample_limit
        if remaining > 0:
            parts.append(f"  …and {remaining} more files")
    return "\n".join(parts)


# ------------------------------------------------------------------ delivery
def send_ntfy(cfg: dict, text: str, title: str, priority: str = "default"):
    topic = cfg.get("NTFY_TOPIC", "")
    if not topic:
        raise RuntimeError("NTFY_TOPIC is not set in config.env")
    url = f"{cfg['NTFY_SERVER'].rstrip('/')}/{urllib.parse.quote(topic)}"
    req = urllib.request.Request(
        url,
        data=text.encode("utf-8"),
        headers={"Title": title, "Priority": priority},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            if resp.status >= 400:
                raise RuntimeError(f"ntfy returned HTTP {resp.status}")
    except urllib.error.HTTPError as exc:
        # Sanitized: HTTPError str() embeds the full URL (ntfy topic = secret)
        raise RuntimeError(f"ntfy delivery failed (HTTP {exc.code})") from None
    except urllib.error.URLError as exc:
        raise RuntimeError(f"ntfy delivery failed ({exc.reason})") from None


def send_telegram(cfg: dict, text: str):
    token = cfg.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = cfg.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        raise RuntimeError("TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not set in config.env")
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = urllib.parse.urlencode({
        "chat_id": chat_id,
        "text": text,
        "disable_web_page_preview": "true",
    }).encode()
    try:
        with urllib.request.urlopen(url, data=payload, timeout=20) as resp:
            body = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        # Sanitized: the request URL contains the bot token — never leak it
        # into exception text (it would land in cron logs).
        raise RuntimeError(f"Telegram delivery failed (HTTP {exc.code})") from None
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Telegram delivery failed ({exc.reason})") from None
    if not body.get("ok"):
        desc = body.get("description", "unknown error")
        raise RuntimeError(f"Telegram API error: {desc}")


def deliver(cfg: dict, text: str, title: str, priority: str = "default"):
    channel = cfg.get("CHANNEL", "ntfy").lower()
    if channel == "telegram":
        send_telegram(cfg, text)
    elif channel == "ntfy":
        send_ntfy(cfg, text, title, priority)
    else:
        raise RuntimeError(f"Unknown CHANNEL '{channel}' (use 'ntfy' or 'telegram')")


# ------------------------------------------------------------------ state
def state_file(cfg: dict, name: str) -> Path:
    d = Path(cfg["STATE_DIR"])
    d.mkdir(parents=True, exist_ok=True)
    return d / name


def read_ts(path: Path, default: datetime) -> datetime:
    try:
        return datetime.fromisoformat(path.read_text().strip())
    except (OSError, ValueError):
        return default


def write_ts(path: Path, ts: datetime):
    path.write_text(ts.isoformat())


def validate_config(cfg: dict, need_channel: bool):
    """Fail fast with clear messages instead of cryptic errors mid-run."""
    try:
        if int(cfg["DIGEST_HOURS"]) <= 0:
            raise ValueError
    except ValueError:
        raise RuntimeError("DIGEST_HOURS must be a positive integer") from None
    if not need_channel:
        return
    channel = cfg.get("CHANNEL", "ntfy").lower()
    if channel not in ("ntfy", "telegram"):
        raise RuntimeError(f"Unknown CHANNEL '{channel}' (use 'ntfy' or 'telegram')")
    if channel == "ntfy" and not cfg.get("NTFY_TOPIC"):
        raise RuntimeError("CHANNEL=ntfy but NTFY_TOPIC is not set in config.env")
    if channel == "telegram" and (
        not cfg.get("TELEGRAM_BOT_TOKEN") or not cfg.get("TELEGRAM_CHAT_ID")
    ):
        raise RuntimeError(
            "CHANNEL=telegram but TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not set")


# ------------------------------------------------------------------ modes
def run_digest(cfg: dict, do_print: bool, raw: bool = False) -> int:
    hours = int(cfg["DIGEST_HOURS"])
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    stats = collect(Path(cfg["COWRIE_LOG"]), since)
    report = build_digest(stats, hours, cfg["SENSOR_NAME"])
    masker = get_masker(cfg, required=not do_print)
    if masker and not raw:
        report = masker.mask(report)
    if do_print:
        print(report)
        return 0
    if stats["connections"] == 0:
        report += "\n\n(Quiet day — no attacks recorded.)"
    title = f"Cowrie digest: {stats['connections']} conn / {len(stats['unique_ips'])} IPs"
    deliver(cfg, report, title)
    print(f"digest sent: {stats['connections']} connections, "
          f"{len(stats['unique_ips'])} unique IPs", file=sys.stderr)
    return 0


ALERT_TAIL_BYTES = 10 * 1024 * 1024  # alerts: scan at most the last 10 MB


def run_alerts(cfg: dict) -> int:
    now = datetime.now(timezone.utc)
    marker = state_file(cfg, "last_alert.ts")
    since = read_ts(marker, now - timedelta(minutes=10))
    successes = []   # (src_ip, username, password)
    downloads = []   # (src_ip, url, shasum)
    latest = since
    for ev in iter_events(Path(cfg["COWRIE_LOG"]), since,
                          tail_bytes=ALERT_TAIL_BYTES):
        eid = ev.get("eventid")
        if eid == "cowrie.login.success":
            successes.append((ev.get("src_ip", "?"),
                              ev.get("username", ""), ev.get("password", "")))
        elif eid == "cowrie.session.file_download":
            downloads.append((ev.get("src_ip", "?"), ev.get("url", "?"),
                              ev.get("shasum", "")))
        if ev["_ts"] > latest:
            latest = ev["_ts"]
    write_ts(marker, max(latest, now))
    if not successes and not downloads:
        return 0
    text = build_alert_summary(successes, downloads, cfg["SENSOR_NAME"])
    masker = get_masker(cfg, required=True)
    if masker:
        text = masker.mask(text)
    deliver(cfg, text, "Cowrie alert", priority="high")
    print(f"sent 1 consolidated alert ({len(successes)} logins, "
          f"{len(downloads)} downloads)", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Cowrie honeypot digest & alerts")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--digest", action="store_true", help="send 24h digest")
    g.add_argument("--alerts", action="store_true", help="send instant alerts since last run")
    g.add_argument("--print", action="store_true",
                   help="print pseudonymized digest, don't send")
    g.add_argument("--print-raw", action="store_true",
                   help="print digest with RAW IPs (local debugging only, never sends)")
    ap.add_argument("--config", default=str(CONFIG_PATH), help="path to config.env")
    args = ap.parse_args()

    cfg = load_config(Path(args.config))
    try:
        validate_config(cfg, need_channel=not (args.print or args.print_raw))
        if args.print:
            return run_digest(cfg, do_print=True)
        if args.print_raw:
            return run_digest(cfg, do_print=True, raw=True)
        if args.digest:
            return run_digest(cfg, do_print=False)
        return run_alerts(cfg)
    except Exception as exc:  # noqa: BLE001 — cron must see the failure reason
        print(f"cowrie-digest ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
