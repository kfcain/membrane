"""Reference tool gateway, dev identity tokens, and human approvals.

What it does:
- Authorizes every tool call through OPA (policy/runtime/*.rego plus the
  generated data document plus the live overrides file).
- Writes one `decision` evidence record per call, with policy and data hashes,
  the action hash, and OpenTelemetry GenAI attribute names.
- Fails closed. Any policy, data, or parse error is a deny with reason policy_error.
- Applies the per agent and tool rate limit. It halves the limit in throttled mode.
- Stores pending approvals and issues single use approval tokens bound to one
  action hash. The approver must differ from the delegator.

What it does NOT prove:
- The dev HMAC identity token is not SPIFFE. It does not prove workload
  attestation, mTLS, or key isolation. Anyone who can read
  var/state/dev-identity.key can mint any identity.
- The default tool backend is a mock. Its `tool_exec` records use mode
  "simulated". The optional directory backend reads real files with mode "live".
- The gateway proves mediation only for calls that pass through it. It does
  not prove that an agent has no other network path to a tool. Egress policy
  (membrane gen) and cluster evidence cover that.
- A decision record shows what the gateway decided. It does not show that a
  real tool honored the decision.
"""
from __future__ import annotations

import sys
from pathlib import Path

from .. import evidence
from ..manifest import DEFAULT_REGISTRY, ManifestError, load_registry


def _serve(args) -> int:
    from .backends import DirectoryKBBackend
    from .opa import policy_files, PolicyError
    from .server import Gateway, GatewayConfig, make_server

    cfg = GatewayConfig()
    backend = None
    try:
        if args.backend == "kb-directory":
            if not args.kb_root:
                raise ValueError("--backend kb-directory requires --kb-root")
            backend = DirectoryKBBackend(args.kb_root)
        elif args.kb_root:
            raise ValueError("--kb-root requires --backend kb-directory")
    except ValueError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 2
    if args.policy_dir:
        cfg.policy_dir = Path(args.policy_dir)
    if args.data:
        cfg.data_path = Path(args.data)
    try:
        files = policy_files(cfg.policy_dir)
    except PolicyError as exc:
        print(f"WARNING {exc}. Every call will deny with policy_error.", file=sys.stderr)
        files = []
    if not cfg.data_path.exists():
        print(f"WARNING data file missing: {cfg.data_path}. Run `membrane gen`. Every call will deny.",
              file=sys.stderr)
    srv = make_server(args.host, args.port, Gateway(cfg, backend=backend))
    host, port = srv.server_address[:2]
    print(f"membrane gateway listening on http://{host}:{port}")
    print(f"  policy files: {', '.join(str(f) for f in files) or '(none)'}")
    print(f"  data:         {cfg.data_path}")
    print(f"  backend:      {args.backend}")
    print(f"  evidence:     {evidence.evidence_dir()}/decision.jsonl, tool_exec.jsonl")
    sys.stdout.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


def _identity_issue(args) -> int:
    from .tokens import DEFAULT_TRUST_DOMAIN, issue_identity, spiffe_id_for
    try:
        reg = load_registry(Path(args.registry))
    except ManifestError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    m = reg.get(args.agent_id)
    if m is None:
        print(f"FAIL agent {args.agent_id!r} is not in the registry", file=sys.stderr)
        return 2
    if args.ttl <= 0:
        print("FAIL --ttl must be positive", file=sys.stderr)
        return 2
    print(issue_identity(m.id, m.sha256, spiffe_id_for(m, args.trust_domain or DEFAULT_TRUST_DOMAIN), args.ttl))
    return 0


def _approve(args) -> int:
    from .approvals import ApprovalError, approve, describe, load, verify_pending_action
    try:
        rec = load(args.approval_id)
    except ApprovalError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    print("Note: the approver is not authenticated in the reference. --approver is a claim. See LIMITS.md.",
          file=sys.stderr)
    print("Review this action before you approve it:", file=sys.stderr)
    print(describe(rec), file=sys.stderr)
    try:
        verify_pending_action(rec)
    except ApprovalError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    if not args.confirm_action_sha256:
        print("NOT SIGNED. To approve, run this command again with "
              "--confirm-action-sha256 <the action_sha256 above>.", file=sys.stderr)
        return 1
    try:
        token, payload, path = approve(args.approval_id, args.approver, args.ttl,
                                       confirm_action_sha256=args.confirm_action_sha256)
    except ApprovalError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    print(token)
    print(f"approval {payload['approval_id']} for {payload['agent_id']} {payload['tool']} "
          f"expires {payload['expires_at']}; evidence written to {path}", file=sys.stderr)
    return 0


def register(sub) -> None:
    p = sub.add_parser("gateway", help="Reference tool gateway.")
    gsub = p.add_subparsers(dest="gateway_cmd", required=True)
    s = gsub.add_parser("serve", help="Serve POST /v1/tools/call and GET /healthz.")
    s.add_argument("--port", type=int, default=8750)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--policy-dir", default=None, help="Default: MEMBRANE_POLICY_DIR or policy/runtime.")
    s.add_argument("--data", default=None, help="Default: MEMBRANE_OPA_DATA or out/generated/opa/data.json.")
    s.add_argument("--backend", choices=["mock", "kb-directory"], default="mock")
    s.add_argument("--kb-root", default=None, help="Read-only corpus for the kb-directory backend.")
    s.set_defaults(func=_serve)

    p = sub.add_parser("identity", help="Dev identity tokens (not SPIFFE).")
    isub = p.add_subparsers(dest="identity_cmd", required=True)
    s = isub.add_parser("issue", help="Print a signed dev identity token for a registered agent.")
    s.add_argument("agent_id")
    s.add_argument("--ttl", type=int, default=3600)
    s.add_argument("--trust-domain", default=None)
    s.add_argument("--registry", default=str(DEFAULT_REGISTRY))
    s.set_defaults(func=_identity_issue)

    p = sub.add_parser("approve", help="Approve one pending action. Prints the approval token.")
    p.add_argument("approval_id")
    p.add_argument("--approver", required=True)
    p.add_argument("--ttl", type=int, default=900)
    p.add_argument("--confirm-action-sha256", default=None,
                   help="The action_sha256 that you reviewed. Without it, the command shows the action and signs nothing.")
    p.set_defaults(func=_approve)
