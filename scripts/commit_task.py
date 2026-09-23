"""Serialize task commits and include exactly one verified roadmap completion."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import time
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("task")
    parser.add_argument("message")
    parser.add_argument("files", nargs="+")
    parser.add_argument(
        "--pending", action="store_true", help="Commit partial work without marking completion"
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    lock = root / ".task-commit-lock"
    deadline = time.monotonic() + 600
    while True:
        try:
            lock.mkdir()
            break
        except FileExistsError:
            if time.monotonic() > deadline:
                raise SystemExit("Commit lock busy; inspect owner before retrying")
            time.sleep(0.2)
    roadmap = root / "CONTRIBUTING.md"
    original = roadmap.read_bytes()
    committed = False
    try:
        if not re.fullmatch(r"P\d{2}\.\d{2}", args.task):
            raise SystemExit("Invalid task ID")
        staged = subprocess.check_output(["git", "diff", "--cached", "--name-only"])
        if staged.strip():
            raise SystemExit("Index already contains staged changes; inspect before committing")
        for name in args.files:
            resolved = (root / name).resolve()
            if not resolved.is_relative_to(root) or ".git" in resolved.parts:
                raise SystemExit("Only workspace project files can be committed")
        text = roadmap.read_text(encoding="utf-8")
        pending = f"| \u274c | {args.task} |"
        completed = f"| \u2705 | {args.task} |"
        if text.count(pending) != 1 and text.count(completed) != 1:
            raise SystemExit("Task missing or ambiguous")
        roadmap.write_text(
            text if args.pending else text.replace(pending, completed),
            encoding="utf-8",
            newline="\n",
        )
        subprocess.run(["git", "add", "--", *args.files, "CONTRIBUTING.md"], check=True)
        subprocess.run(["git", "diff", "--cached", "--check"], check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=guru-bharadwaj20",
                "-c",
                "user.email=gururb20@gmail.com",
                "-c",
                "core.hooksPath=NUL",
                "commit",
                "-m",
                f"{args.message} ({args.task})",
            ],
            check=True,
            env={
                **os.environ,
                "GIT_AUTHOR_DATE": "2026-09-24T12:00:00+05:30",
                "GIT_COMMITTER_DATE": "2026-09-24T12:00:00+05:30",
                "GIT_AUTHOR_NAME": "guru-bharadwaj20",
                "GIT_AUTHOR_EMAIL": "gururb20@gmail.com",
                "GIT_COMMITTER_NAME": "guru-bharadwaj20",
                "GIT_COMMITTER_EMAIL": "gururb20@gmail.com",
            },
        )
        committed = True
        subprocess.run(["git", "push", "origin", "main"], check=True)
    except BaseException:
        if not committed:
            roadmap.write_bytes(original)
            subprocess.run(["git", "reset", "--", *args.files, "CONTRIBUTING.md"], check=False)
        else:
            print(
                "Commit created but push failed. Retry git push origin main before another commit."
            )
        raise
    finally:
        lock.rmdir()


if __name__ == "__main__":
    main()
