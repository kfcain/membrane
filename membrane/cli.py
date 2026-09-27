"""membrane CLI. Each subsystem registers its own subcommands.

Contract: a subsystem module exposes `register(subparsers)` and sets
`func` on each parser with `set_defaults(func=...)`. `func(args)` returns
an int exit code.
"""
from __future__ import annotations

import argparse
import importlib
import sys

SUBSYSTEMS = [
    "membrane.registry_cmd",   # validate, hash, list (shared)
    "membrane.gen",            # gen, gen --check
    "membrane.gateway",        # gateway serve, identity issue, approve
    "membrane.canary",         # canary run
    "membrane.respond",        # respond
    "membrane.checks",         # checks run
]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="membrane", description="Agent containment and evidence reference.")
    sub = p.add_subparsers(dest="command", required=True)
    for name in SUBSYSTEMS:
        try:
            mod = importlib.import_module(name)
        except ModuleNotFoundError as exc:
            if exc.name == name:
                continue  # subsystem not built yet
            raise
        mod.register(sub)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
