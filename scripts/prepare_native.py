"""Project-local Rust standard-library component; no machine installation."""

from __future__ import annotations

import hashlib
import shutil
import tarfile
import urllib.request
from pathlib import Path

VERSION = "1.92.0"
COMPONENT = f"rust-std-{VERSION}-x86_64-pc-windows-gnu"
BASE = "https://static.rust-lang.org/dist/" + COMPONENT + ".tar.xz"
directory = Path("artifacts/native-toolchain")
directory.mkdir(parents=True, exist_ok=True)
archive = directory / (COMPONENT + ".tar.xz")
with urllib.request.urlopen(BASE + ".sha256", timeout=30) as response:
    expected = response.read().decode().split()[0]
urllib.request.urlretrieve(BASE, archive)
if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
    raise SystemExit("Rust component checksum mismatch")
with tarfile.open(archive) as package:
    package.extractall(directory, filter="data")
source = directory / COMPONENT / "rust-std-x86_64-pc-windows-gnu" / "lib"
destination = directory / "sysroot" / "lib"
shutil.copytree(source, destination, dirs_exist_ok=True)
print(destination.parent.resolve())
