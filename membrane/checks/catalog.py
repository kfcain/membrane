"""Load and validate the check catalog (controls/checks.yaml).

The catalog is the only place that maps a check to controls.
See docs/CONTRACTS.md section 7.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ..evidence import KINDS
from ..manifest import REPO_ROOT

CATALOG_PATH = REPO_ROOT / "controls" / "checks.yaml"

NIST_ID = re.compile(r"^[A-Z]{2}-\d{1,2}(\(\d{1,2}\))?$")
SCF_AO_ID = re.compile(r"^[A-Z]{3}-\d{2}(\.\d{1,2})?_A\d{2}$")
CHECK_ID = re.compile(r"^AGT-[A-Z]{2,3}-\d{2}$")
REQUIRED = ("id", "title", "question", "evidence_kinds", "max_age_hours", "target", "controls")


class CatalogError(Exception):
    """The check catalog is malformed."""


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    question: str
    evidence_kinds: tuple[str, ...]
    supporting_kinds: tuple[str, ...]
    max_age_hours: float
    target: str
    remediation: str
    nist_800_53: tuple[str, ...]
    scf_ao: tuple[str, ...]
    raw: dict = field(repr=False, compare=False, default_factory=dict)

    @property
    def all_kinds(self) -> tuple[str, ...]:
        return self.evidence_kinds + tuple(k for k in self.supporting_kinds if k not in self.evidence_kinds)

    def frameworks(self) -> dict[str, tuple[str, ...]]:
        return {"nist_800_53": self.nist_800_53, "scf_ao": self.scf_ao}


@dataclass(frozen=True)
class Catalog:
    checks: tuple[Check, ...]
    scf_pin: dict
    path: Path

    def by_id(self) -> dict[str, Check]:
        return {c.id: c for c in self.checks}


def _fail(msg: str) -> None:
    raise CatalogError(msg)


def load_catalog(path: Path | None = None) -> Catalog:
    path = Path(path or CATALOG_PATH)
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CatalogError(f"{path}: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("checks"), list):
        _fail(f"{path}: top level must be a mapping with a 'checks' list")
    seen: set[str] = set()
    out: list[Check] = []
    for n, item in enumerate(doc["checks"]):
        where = f"{path}: checks[{n}]"
        if not isinstance(item, dict):
            _fail(f"{where}: must be a mapping")
        missing = [k for k in REQUIRED if k not in item]
        if missing:
            _fail(f"{where}: missing {missing}")
        cid = item["id"]
        if not CHECK_ID.match(str(cid)):
            _fail(f"{where}: bad check id {cid!r}")
        if cid in seen:
            _fail(f"{where}: duplicate check id {cid}")
        seen.add(cid)
        kinds = tuple(item["evidence_kinds"] or ())
        support = tuple(item.get("supporting_kinds") or ())
        if not kinds:
            _fail(f"{where}: evidence_kinds must not be empty")
        for k in kinds + support:
            if k not in KINDS or k == "check_result":
                _fail(f"{where}: unknown evidence kind {k!r}")
        try:
            max_age = float(item["max_age_hours"])
        except (TypeError, ValueError):
            _fail(f"{where}: max_age_hours must be a number")
        if max_age <= 0:
            _fail(f"{where}: max_age_hours must be positive")
        controls = item["controls"] or {}
        nist = tuple(controls.get("nist_800_53") or ())
        scf = tuple(controls.get("scf_ao") or ())
        for c in nist:
            if not NIST_ID.match(c):
                _fail(f"{where}: bad NIST SP 800-53 id {c!r}")
        for a in scf:
            if not SCF_AO_ID.match(a):
                _fail(f"{where}: bad SCF assessment objective id {a!r}")
        if len(set(nist)) != len(nist) or len(set(scf)) != len(scf):
            _fail(f"{where}: duplicate control id")
        out.append(Check(
            id=cid, title=str(item["title"]), question=str(item["question"]).strip(),
            evidence_kinds=kinds, supporting_kinds=support, max_age_hours=max_age,
            target=" ".join(str(item["target"]).split()),
            remediation=" ".join(str(item.get("remediation") or "").split()),
            nist_800_53=nist, scf_ao=scf, raw=item,
        ))
    return Catalog(checks=tuple(out), scf_pin=dict(doc.get("scf_pin") or {}), path=path)


def nist_to_oscal(control_id: str) -> str:
    """CM-8(3) -> cm-8.3 (the NIST OSCAL catalog id form)."""
    m = re.match(r"^([A-Z]{2})-(\d+)(?:\((\d+)\))?$", control_id)
    if not m:
        raise CatalogError(f"bad NIST id {control_id!r}")
    fam, num, enh = m.groups()
    return f"{fam.lower()}-{int(num)}" + (f".{int(enh)}" if enh else "")


def scf_control_ref(ao_id: str) -> str:
    """AAT-07.1_A02 -> AAT-07.1."""
    return ao_id.rsplit("_", 1)[0]
