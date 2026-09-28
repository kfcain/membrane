"""Send a short, realistic set of tool calls through a running gateway.

The demo uses this script to make live decision, approval, and tool_exec
evidence. Each step prints the expected and the observed decision. The
script exits 1 if any observed decision differs from the expected one.
"""
from __future__ import annotations

import os
import sys

from membrane.gateway.approvals import approve
from membrane.gateway.client import call_tool, default_gateway_url
from membrane.gateway.tokens import issue_identity, spiffe_id_for
from membrane.manifest import load_registry

URL = os.environ.get("MEMBRANE_GATEWAY_URL", default_gateway_url())
REG = load_registry()


def token(agent_id: str) -> str:
    m = REG[agent_id]
    return issue_identity(m.id, m.sha256, spiffe_id_for(m), 600)


STEPS = [
    ("kb-reader searches the knowledge base", "kb-reader",
     {"tool": "kb.search", "resource": "kb/vpn-setup", "args": {"q": "vpn"}, "delegator": "alice@example.com"}, "allow"),
    ("ticket-triager routes a ticket", "ticket-triager",
     {"tool": "tickets.route", "resource": "ticket/SD-4410", "args": {"queue": "network"}, "delegator": None}, "allow"),
    ("invoice-reconciler reads invoices", "invoice-reconciler",
     {"tool": "erp.read_invoices", "resource": "vendor/ACME", "args": {"period": "2026-09"}, "delegator": "carol@example.com"}, "allow"),
    ("invoice-reconciler posts an adjustment (irreversible)", "invoice-reconciler",
     {"tool": "erp.post_adjustment", "resource": "invoice/INV-1001", "args": {"amount": -120.50}, "delegator": "carol@example.com"},
     "require_approval"),
    ("invoice-reconciler sends a vendor notice with no delegator", "invoice-reconciler",
     {"tool": "email.send_vendor_notice", "resource": "vendor/ACME", "args": {"template": "adj"}, "delegator": None}, "deny"),
    ("ticket-triager tries an ERP tool outside its manifest", "ticket-triager",
     {"tool": "erp.post_adjustment", "resource": "invoice/INV-1001", "args": {"amount": -1}, "delegator": None}, "deny"),
    ("code-runner runs analysis code in the sandbox", "code-runner",
     {"tool": "sandbox.exec", "resource": "session/7781", "args": {"lang": "python"}, "delegator": "dave@example.com"}, "allow"),
]


def main() -> int:
    failures = 0
    pending = None
    for title, agent, body, expected in STEPS:
        status, resp = call_tool(URL, token(agent), body)
        observed = resp.get("decision")
        ok = observed == expected
        failures += 0 if ok else 1
        print(f"{'OK  ' if ok else 'FAIL'} {title}: expected {expected}, observed {observed} {resp.get('reasons', [])}")
        if observed == "require_approval":
            pending = (agent, body, resp["approval_id"])
    if pending:
        agent, body, approval_id = pending
        # The approver reviews the stored action and restates its hash.
        from membrane.gateway.approvals import load
        reviewed = load(approval_id)["action_sha256"]
        approval_token, _, _ = approve(approval_id, "bob@example.com", confirm_action_sha256=reviewed)
        status, resp = call_tool(URL, token(agent), {**body, "approval_token": approval_token})
        ok = resp.get("decision") == "allow"
        failures += 0 if ok else 1
        print(f"{'OK  ' if ok else 'FAIL'} bob@example.com approves, the agent retries: expected allow, observed {resp.get('decision')}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
