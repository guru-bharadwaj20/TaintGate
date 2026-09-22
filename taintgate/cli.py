"""TaintGate command-line entry point."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from taintgate.audit.log import AuditLog, checkpoint, inclusion_proof, verify_checkpoint

def main() -> None:
    parser = argparse.ArgumentParser(prog="taintgate")
    commands = parser.add_subparsers(dest="command",required=True)
    audit = commands.add_parser("audit")
    audit.add_argument("operation",choices=["verify","prove","checkpoint"])
    audit.add_argument("database")
    audit.add_argument("--index",type=int,default=0)
    audit.add_argument("--anchor",type=Path)
    args = parser.parse_args()
    log = AuditLog(args.database)
    try:
        if args.operation == "verify":
            valid = verify_checkpoint(log,json.loads(args.anchor.read_text())) if args.anchor else log.verify()
            print(json.dumps({"valid":valid,"anchored":args.anchor is not None}))
            if not valid:
                raise SystemExit(1)
        elif args.operation == "checkpoint":
            print(json.dumps(checkpoint(log)))
        else:
            print(json.dumps(inclusion_proof(log,args.index)))
    finally:
        log.close()

if __name__ == "__main__":
    main()
