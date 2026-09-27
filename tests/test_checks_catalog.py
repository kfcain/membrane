"""Catalog shape, SCF id existence against Beacon's pin, and the generated doc."""
from __future__ import annotations

import pytest

from membrane.checks.catalog import CatalogError, load_catalog, nist_to_oscal
from membrane.checks.doc import DOC_PATH, load_rows, render, rows_path, verify_scf_ids
from membrane.checks.evaluators import EVALUATORS

EXPECTED = ["AGT-INV-01", "AGT-INV-02", "AGT-IAM-01", "AGT-IAM-02", "AGT-AU-01", "AGT-AC-01",
            "AGT-AC-02", "AGT-SC-01", "AGT-CM-01", "AGT-TST-01", "AGT-IR-01"]


def test_catalog_has_every_check_and_an_evaluator():
    cat = load_catalog()
    assert [c.id for c in cat.checks] == EXPECTED
    assert set(EVALUATORS) == set(EXPECTED)
    for c in cat.checks:
        assert c.question.endswith("?")
        assert c.nist_800_53, c.id
        assert c.remediation


def test_catalog_prose_avoids_banned_words():
    text = load_catalog().path.read_text().lower()
    for word in ("in place", "compliant", "evidenced", "proven", "—"):
        assert word not in text


def test_nist_to_oscal():
    assert nist_to_oscal("CM-8") == "cm-8"
    assert nist_to_oscal("CM-8(3)") == "cm-8.3"
    assert nist_to_oscal("SC-7(5)") == "sc-7.5"


def test_bad_catalog_rejected(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("checks:\n- {id: AGT-X-01, title: t, question: q?, evidence_kinds: [nope], max_age_hours: 1, "
                 "target: t, controls: {nist_800_53: [], scf_ao: []}}\n")
    with pytest.raises(CatalogError):
        load_catalog(p)
    p.write_text("checks:\n- {id: AGT-XX-01, title: t, question: q?, evidence_kinds: [inventory], max_age_hours: 1, "
                 "target: t, controls: {nist_800_53: [CM8], scf_ao: []}}\n")
    with pytest.raises(CatalogError):
        load_catalog(p)


rows_available = pytest.mark.skipif(not rows_path().is_file(), reason="Beacon SCF rows.json not present")


@rows_available
def test_every_scf_id_exists_in_pinned_rows():
    cat = load_catalog()
    rows = load_rows(cat)
    assert verify_scf_ids(cat, rows) == []
    assert len(rows) == 6446


@rows_available
def test_rows_hash_mismatch_fails_closed(tmp_path):
    bad = tmp_path / "rows.json"
    bad.write_text(rows_path().read_text() + " ")
    with pytest.raises(CatalogError):
        load_rows(load_catalog(), bad)


@rows_available
def test_generated_doc_is_current():
    cat = load_catalog()
    assert DOC_PATH.read_text() == render(cat, load_rows(cat)), "rerun: membrane checks doc"
