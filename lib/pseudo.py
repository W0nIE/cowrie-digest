"""Pseudonymization of personal data (attacker IPs) via HMAC-SHA256.

Golden rule (see docs/PII-PROCESSING.md): raw IPs never leave the server.
All outbound text passes through mask(), which replaces every IPv4 address
with a stable pseudonym (ip-<12 hex chars>). Properties:

- Deterministic: same IP -> same pseudonym (statistics keep working)
- Keyed (HMAC): without the secret key the pseudonym cannot be reversed,
  not even by brute-forcing the ~4B IPv4 space
- The key lives only on the server (0600, gitignored) and never travels
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from pathlib import Path

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PSEUDO_PREFIX = "ip-"
TAG_LEN = 12  # hex chars of HMAC output kept in the pseudonym


class Pseudonymizer:
    def __init__(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)) or len(bytes(key)) < 16:
            raise ValueError("HMAC key must be at least 16 bytes")
        self._key = bytes(key)

    def pseudo_ip(self, ip: str) -> str:
        """Stable pseudonym for one IPv4 address."""
        tag = hmac.new(self._key, f"ip:{ip}".encode(), hashlib.sha256).hexdigest()
        return f"{PSEUDO_PREFIX}{tag[:TAG_LEN]}"

    def mask(self, text: str) -> str:
        """Replace every valid IPv4 address in text with its pseudonym."""
        def repl(match: re.Match) -> str:
            token = match.group(0)
            if any(int(part) > 255 for part in token.split(".")):
                return token  # looks like an IP but isn't a valid one
            return self.pseudo_ip(token)
        return IPV4_RE.sub(repl, text)


def load_key(path: Path) -> bytes:
    """Load the HMAC key (hex-encoded, one line) from disk."""
    data = path.read_text(encoding="ascii").strip()
    try:
        key = bytes.fromhex(data)
    except ValueError as exc:
        raise ValueError(f"{path}: key must be hex-encoded") from exc
    if len(key) < 16:
        raise ValueError(f"{path}: key too short ({len(key)} bytes)")
    return key


def ensure_key(path: Path) -> bytes:
    """Load the key, generating a fresh random one on first use."""
    path = Path(path)
    if path.exists():
        return load_key(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    fd = path.open("w", encoding="ascii")
    try:
        fd.write(key.hex() + "\n")
    finally:
        fd.close()
    path.chmod(0o600)
    return key
