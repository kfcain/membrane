"""Dev identity and approval tokens (CONTRACTS section 6).

Format: base64url(canonical JSON payload) + "." + base64url(HMAC-SHA256(key, payload bytes)).
The HMAC covers the decoded JSON payload bytes. base64url has no padding.
`exp` is an integer Unix time in seconds.

This is NOT SPIFFE. A shared HMAC key proves only that the holder of the
key made the token. Production uses X.509 SVIDs over mTLS from SPIRE.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

from ..manifest import Manifest, canonical_json, sha256_hex
from .state import state_dir

DEFAULT_TRUST_DOMAIN = "example.org"
IDENTITY_KEY = "dev-identity.key"
APPROVAL_KEY = "dev-approval.key"
IDENTITY_FIELDS = ("agent_id", "manifest_sha256", "spiffe_id", "exp")
APPROVAL_FIELDS = ("approval_id", "action_sha256", "approver", "exp")


class TokenError(Exception):
    """A token failed to parse, failed its signature check, or expired."""


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load_key(name: str) -> bytes:
    """Read the key file. Create it with mode 0600 on first use."""
    path = state_dir() / name
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, "wb") as fh:
            fh.write(secrets.token_bytes(32))
    key = Path(path).read_bytes()
    if len(key) < 32:
        raise TokenError(f"{path}: key is shorter than 32 bytes")
    return key


def sign(payload: dict, key_name: str) -> str:
    body = canonical_json(payload)
    mac = hmac.new(load_key(key_name), body, hashlib.sha256).digest()
    return f"{_b64e(body)}.{_b64e(mac)}"


def decode_unverified(token: str) -> dict:
    """Return the payload without any check. Use only for logging a claim."""
    try:
        body_s, _ = token.split(".", 1)
        obj = json.loads(_b64d(body_s))
    except Exception as exc:  # noqa: BLE001 - any parse failure is the same outcome
        raise TokenError(f"malformed token: {exc}") from exc
    if not isinstance(obj, dict):
        raise TokenError("token payload is not an object")
    return obj


def verify(token: str, key_name: str, fields: tuple[str, ...], now: float | None = None) -> dict:
    """Check format, HMAC, required fields, and exp. Return the payload."""
    if not isinstance(token, str) or token.count(".") != 1:
        raise TokenError("malformed token")
    body_s, mac_s = token.split(".")
    try:
        body = _b64d(body_s)
        mac = _b64d(mac_s)
    except Exception as exc:  # noqa: BLE001
        raise TokenError("malformed token encoding") from exc
    expected = hmac.new(load_key(key_name), body, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise TokenError("bad signature")
    try:
        obj = json.loads(body)
    except ValueError as exc:
        raise TokenError("payload is not JSON") from exc
    if not isinstance(obj, dict) or set(obj) != set(fields):
        raise TokenError(f"payload fields must be exactly {sorted(fields)}")
    exp = obj["exp"]
    if not isinstance(exp, int) or isinstance(exp, bool):
        raise TokenError("exp must be an integer")
    if exp <= (time.time() if now is None else now):
        raise TokenError("token expired")
    return obj


def spiffe_id_for(manifest: Manifest, trust_domain: str = DEFAULT_TRUST_DOMAIN) -> str:
    """CONTRACTS section 6: spiffe://<td>/ns/<namespace>/sa/<service_account>.

    Manifests without a k8s namespace and service account (lambda, saas) get
    spiffe://<td>/membrane/agent/<id>. That path is a local convention.
    """
    rt = manifest.spec.get("runtime", {})
    if rt.get("namespace") and rt.get("service_account"):
        return f"spiffe://{trust_domain}/ns/{rt['namespace']}/sa/{rt['service_account']}"
    return f"spiffe://{trust_domain}/membrane/agent/{manifest.id}"


def issue_identity(agent_id: str, manifest_sha256: str, spiffe_id: str, ttl: int = 3600) -> str:
    return sign({"agent_id": agent_id, "manifest_sha256": manifest_sha256,
                 "spiffe_id": spiffe_id, "exp": int(time.time()) + int(ttl)}, IDENTITY_KEY)


def verify_identity(token: str) -> dict:
    return verify(token, IDENTITY_KEY, IDENTITY_FIELDS)


def issue_approval(approval_id: str, action_sha256: str, approver: str, exp: int) -> str:
    return sign({"approval_id": approval_id, "action_sha256": action_sha256,
                 "approver": approver, "exp": int(exp)}, APPROVAL_KEY)


def verify_approval(token: str) -> dict:
    return verify(token, APPROVAL_KEY, APPROVAL_FIELDS)


def action_sha256(agent_id: str, tool: str, resource, args) -> str:
    """sha256 of canonical JSON of {agent_id, tool, resource, args}."""
    return sha256_hex(canonical_json({"agent_id": agent_id, "tool": tool, "resource": resource, "args": args}))
