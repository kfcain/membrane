"""Doc claims stay inside what the code supports (review R-25)."""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_r25_canary_step_does_not_claim_proof():
    text = (REPO / "README.md").read_text()
    assert "is proof that a gate works" not in text
    assert "Each denial is a record that the gateway path denied that action." in text


def test_r25_architecture_states_the_parse_rules_behind_one_action_one_hash():
    text = (REPO / "docs" / "ARCHITECTURE.md").read_text()
    assert "A token for action A cannot approve action B." not in text or "rejects inexact" in text
