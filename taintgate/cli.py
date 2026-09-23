"""TaintGate command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from taintgate.audit.log import AuditLog, checkpoint, inclusion_proof, verify_checkpoint


def main() -> None:
    parser = argparse.ArgumentParser(prog="taintgate")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("demo", help="Run isolated trusted-send and injection scenarios")
    ui = commands.add_parser("ui", help="Serve the authenticated local dry-run interface")
    ui.add_argument("--port", type=int, default=8000)
    audit = commands.add_parser("audit")
    audit.add_argument("operation", choices=["verify", "prove", "checkpoint"])
    audit.add_argument("database")
    audit.add_argument("--index", type=int, default=0)
    audit.add_argument("--anchor", type=Path)
    args = parser.parse_args()
    if args.command == "demo":
        from taintgate.demo import demo

        print(json.dumps(asyncio.run(demo()), indent=2))
        return
    if args.command == "ui":
        import uvicorn

        from taintgate.ui.app import create_app

        app = create_app()
        print("Local session token: " + app.state.token)
        uvicorn.run(app, host="127.0.0.1", port=args.port)
        return
    log = AuditLog(args.database)
    try:
        if args.operation == "verify":
            valid = (
                verify_checkpoint(log, json.loads(args.anchor.read_text()))
                if args.anchor
                else log.verify()
            )
            print(json.dumps({"valid": valid, "anchored": args.anchor is not None}))
            if not valid:
                raise SystemExit(1)
        elif args.operation == "checkpoint":
            print(json.dumps(checkpoint(log)))
        else:
            print(json.dumps(inclusion_proof(log, args.index)))
    finally:
        log.close()


if __name__ == "__main__":
    main()
