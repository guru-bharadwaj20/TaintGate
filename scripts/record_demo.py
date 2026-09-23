"""Record synthetic CLI evidence and render an explicitly labelled demo video."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import subprocess
import textwrap
from typing import Any

from taintgate.audit.log import AuditLog, Event, checkpoint, verify_checkpoint
from taintgate.demo import demo, make_demo


async def evidence() -> dict[str, Any]:
    results = await demo()
    app, server = make_demo()
    try:
        server.tools["read"]["description"] = "Changed after approval"
        changed = await app.run("mail = email__read()")
        results["tool_change"] = {"status": changed.status, "diffs": changed.metadata_diffs}
    finally:
        app.audit.close()
        if app.gateway.guard is not None:
            app.gateway.guard.pins.close()
    log = AuditLog()
    log.append(Event("run_start", "synthetic", {}))
    log.append(Event("run_end", "synthetic", {}))
    anchor = checkpoint(log)
    log.connection.execute("DELETE FROM events WHERE seq=2")
    results["anchored_truncation_detected"] = not verify_checkpoint(log, anchor)
    log.connection.execute("UPDATE events SET event=x'00' WHERE seq=1")
    results["edit_detected"] = not log.verify()
    log.close()
    return results


def render_video(results: dict[str, Any], target: Path) -> None:
    from PIL import Image, ImageDraw, ImageFont
    import imageio_ffmpeg

    scenes = [
        ("TaintGate", "Rendered demonstration from recorded synthetic CLI output.\nNo real email, files or payments.\nSecurity comes from deterministic labels and policies."),
        ("Trust boundaries", "Trusted request -> restricted planner program\nStatic checker -> labelled interpreter\nEvery tool call -> policy -> MCP metadata checks\nUntrusted extraction output stays untrusted."),
        ("Trusted action", f"Trusted send: {results['trusted_status']}\nExactly one synthetic send was recorded:\n{json.dumps(results['recorded_sends'], indent=2)}"),
        ("Poisoned email", f"Attacker requests invoice forwarding to evil@example.net.\nRuntime status: {results['attack_status']}\nThe attacker-selected send is denied.\nRecorded sends remain limited to the trusted fixture."),
        ("Changed tool metadata", f"A server changed its description after approval.\nStatus: {results['tool_change']['status']}\nPinned metadata quarantines the tool.\n" + "\n".join(results['tool_change']['diffs'])),
        ("Tamper evidence", f"Audit verified before mutation: {results['audit_valid']}\nEdited event detected: {results['edit_detected']}\nTail deletion detected with trusted anchor: {results['anchored_truncation_detected']}\nAn unanchored chain cannot detect a rewritten history.\nThese fixtures are not AgentDojo measurements."),
    ]
    target.parent.mkdir(parents=True, exist_ok=True)
    binary = imageio_ffmpeg.get_ffmpeg_exe()
    process = subprocess.Popen([binary, "-y", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", "960x540", "-r", "1", "-i", "-", "-an", "-c:v", "libx264", "-pix_fmt", "yuv420p", "-movflags", "+faststart", str(target)], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    font = ImageFont.load_default(size=19)
    title = ImageFont.load_default(size=30)
    assert process.stdin is not None
    for heading, body in scenes:
        frame = Image.new("RGB", (960, 540), "#101a23")
        draw = ImageDraw.Draw(frame)
        draw.text((40, 35), heading, font=title, fill="#8ee0b8")
        lines = "\n".join(textwrap.fill(line, width=76) for line in body.splitlines())
        draw.multiline_text((40, 105), lines, font=font, fill="#e6edf4", spacing=9)
        draw.text((40, 505), "Synthetic recorded evidence | TaintGate", font=font, fill="#a6b9ca")
        for _ in range(30):
            process.stdin.write(frame.tobytes())
    process.stdin.close()
    process.stdin = None
    _, errors = process.communicate(timeout=60)
    if process.returncode:
        raise RuntimeError(errors.decode(errors="replace"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--video", action="store_true")
    args = parser.parse_args()
    results = asyncio.run(evidence())
    Path("benchmarks/demo_results.json").write_text(json.dumps(results, indent=2) + "\n")
    if args.video:
        render_video(results, Path("docs/assets/demo.mp4"))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
