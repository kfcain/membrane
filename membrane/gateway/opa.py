"""OPA evaluation for the gateway (CONTRACTS section 3).

The gateway loads policy/runtime/*.rego (not *_test.rego) and the generated
data document. It merges the overrides file under membrane.overrides and
queries data.membrane.authz.result. Two transports exist:

- `opa eval` (default). The merged data goes to a temp file. The input goes on stdin.
- OPA REST (MEMBRANE_OPA_URL). The gateway PUTs /v1/data/membrane/manifests and
  /v1/data/membrane/overrides, then POSTs
  /v1/data/membrane/authz/result. The remote OPA must already hold the policy.
  policy_sha256 then describes the local files, not what the remote server loaded.

Any failure raises PolicyError. The caller denies with reason policy_error.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from ..manifest import REPO_ROOT, canonical_json, sha256_hex

QUERY = "data.membrane.authz.result"
DECISIONS = {"allow", "deny", "require_approval"}


class PolicyError(Exception):
    """Policy or data could not be loaded or evaluated."""


def default_policy_dir() -> Path:
    return Path(os.environ.get("MEMBRANE_POLICY_DIR", REPO_ROOT / "policy" / "runtime"))


def default_data_path() -> Path:
    return Path(os.environ.get("MEMBRANE_OPA_DATA", REPO_ROOT / "out" / "generated" / "opa" / "data.json"))


def policy_files(policy_dir: Path) -> list[Path]:
    files = sorted(p for p in Path(policy_dir).glob("*.rego") if not p.name.endswith("_test.rego"))
    if not files:
        raise PolicyError(f"no policy files in {policy_dir}")
    return files


def policy_sha256(files: list[Path]) -> str:
    """sha256 of canonical JSON {file name: sha256 of file bytes}."""
    return sha256_hex(canonical_json({p.name: sha256_hex(p.read_bytes()) for p in files}))


@dataclass
class Snapshot:
    """The exact policy and data one decision used."""
    files: list[Path]
    policy_sha256: str
    data: dict
    data_sha256: str


def snapshot(policy_dir: Path, data_path: Path, overrides: dict) -> Snapshot:
    files = policy_files(policy_dir)
    try:
        generated = json.loads(Path(data_path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyError(f"data file missing: {data_path}") from exc
    except ValueError as exc:
        raise PolicyError(f"data file does not parse: {data_path}: {exc}") from exc
    manifests = (generated.get("membrane") or {}).get("manifests") if isinstance(generated, dict) else None
    if not isinstance(manifests, dict):
        raise PolicyError(f"{data_path}: missing membrane.manifests")
    data = {"membrane": {"manifests": manifests, "overrides": overrides}}
    return Snapshot(files, policy_sha256(files), data, sha256_hex(canonical_json(data)))


def _check_result(value) -> dict:
    if not isinstance(value, dict) or value.get("decision") not in DECISIONS:
        raise PolicyError(f"policy returned an invalid result: {value!r}")
    reasons = value.get("reasons")
    if not isinstance(reasons, list) or not reasons or not all(isinstance(r, str) for r in reasons):
        raise PolicyError(f"policy returned invalid reasons: {reasons!r}")
    return {"decision": value["decision"], "reasons": list(reasons)}


def evaluate(snap: Snapshot, input_doc: dict, *, opa_bin: str | None = None,
             opa_url: str | None = None, timeout: float = 10.0) -> dict:
    opa_url = opa_url if opa_url is not None else os.environ.get("MEMBRANE_OPA_URL")
    if opa_url:
        return _evaluate_rest(opa_url.rstrip("/"), snap, input_doc, timeout)
    return _evaluate_cli(opa_bin or os.environ.get("MEMBRANE_OPA_BIN", "opa"), snap, input_doc, timeout)


def _evaluate_cli(opa_bin: str, snap: Snapshot, input_doc: dict, timeout: float) -> dict:
    with tempfile.TemporaryDirectory(prefix="membrane-opa-") as td:
        data_file = Path(td) / "data.json"
        data_file.write_bytes(canonical_json(snap.data))
        cmd = [opa_bin, "eval", "--format=json", "--stdin-input"]
        for f in snap.files:
            cmd += ["-d", str(f)]
        cmd += ["-d", str(data_file), QUERY]
        try:
            proc = subprocess.run(cmd, input=json.dumps(input_doc), capture_output=True,
                                  text=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PolicyError(f"opa eval failed to run: {exc}") from exc
    if proc.returncode != 0:
        raise PolicyError(f"opa eval exit {proc.returncode}: {proc.stderr.strip()[:500]}")
    try:
        out = json.loads(proc.stdout)
        value = out["result"][0]["expressions"][0]["value"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise PolicyError(f"opa eval returned no result for {QUERY}") from exc
    return _check_result(value)


def _http(method: str, url: str, body: dict, timeout: float) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator-set URL
        raw = resp.read()
    return json.loads(raw) if raw.strip() else {}


def _evaluate_rest(base: str, snap: Snapshot, input_doc: dict, timeout: float) -> dict:
    try:
        # Write each leaf. A PUT on /membrane itself would conflict with the policy package path.
        _http("PUT", f"{base}/v1/data/membrane/manifests", snap.data["membrane"]["manifests"], timeout)
        _http("PUT", f"{base}/v1/data/membrane/overrides", snap.data["membrane"]["overrides"], timeout)
        out = _http("POST", f"{base}/v1/data/membrane/authz/result", {"input": input_doc}, timeout)
    except Exception as exc:  # noqa: BLE001 - every transport failure fails closed
        raise PolicyError(f"OPA REST call failed: {exc}") from exc
    if "result" not in out:
        raise PolicyError(f"OPA REST returned no result for {QUERY}")
    return _check_result(out["result"])
