"""Load, validate, and hash agent manifests.

Every other module reads manifests through this module. Do not parse
registry files directly anywhere else.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jsonschema
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schema" / "agent-manifest.v1.schema.json"
DEFAULT_REGISTRY = REPO_ROOT / "registry" / "agents"


class ManifestError(Exception):
    """A manifest failed to load or failed schema validation."""


def canonical_json(obj: Any) -> bytes:
    """Stable JSON bytes: sorted keys, no spaces, UTF-8. NaN and Infinity raise ValueError."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Manifest:
    doc: dict
    path: Path

    @property
    def id(self) -> str:
        return self.doc["metadata"]["id"]

    @property
    def spec(self) -> dict:
        return self.doc["spec"]

    @property
    def tier(self) -> int:
        return int(self.doc["spec"]["tier"])

    @property
    def sha256(self) -> str:
        """Hash of the canonical JSON form. File formatting does not change it."""
        return sha256_hex(canonical_json(self.doc))


def _schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


def validate_doc(doc: dict) -> None:
    validator = jsonschema.Draft202012Validator(_schema(), format_checker=jsonschema.FormatChecker())
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    if errors:
        msgs = [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors]
        raise ManifestError("; ".join(msgs))


def load_manifest(path: Path) -> Manifest:
    try:
        doc = yaml.safe_load(Path(path).read_text())
    except yaml.YAMLError as exc:
        raise ManifestError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise ManifestError(f"{path}: manifest must be a mapping")
    try:
        validate_doc(doc)
    except ManifestError as exc:
        raise ManifestError(f"{path}: {exc}") from exc
    return Manifest(doc=doc, path=Path(path))


def load_registry(directory: Path | None = None) -> dict[str, Manifest]:
    """Load every *.yaml manifest. Fail closed on any invalid file or duplicate id."""
    directory = Path(directory or DEFAULT_REGISTRY)
    out: dict[str, Manifest] = {}
    for path in sorted(directory.glob("*.yaml")):
        m = load_manifest(path)
        if m.id in out:
            raise ManifestError(f"duplicate agent id {m.id!r} in {path} and {out[m.id].path}")
        if path.stem != m.id:
            raise ManifestError(f"{path}: file name must equal metadata.id ({m.id})")
        out[m.id] = m
    return out
