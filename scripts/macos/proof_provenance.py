#!/usr/bin/env python3
"""Seal isolated proof/verifier executables to their actual build inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "target/macos"
PIN = "f8dcbdf8124a3f1528146bb01d539c55545cbb3d"
ENVIRONMENT = ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "DEVELOPER_DIR", "TOOLCHAINS", "SDKROOT")


def sha(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def paths(kind):
    if kind == "hybrid":
        return BASE / "hybrid/release/hemi-macos-hybrid-proof", BASE / "hybrid-metadata.json"
    if kind == "verifier":
        return BASE / "verifier/release/hemi-macos-proof", BASE / "verifier-metadata.json"
    raise ValueError(f"unknown proof build kind: {kind}")


def source_state(kind, engine=None):
    files = [ROOT / "scripts/macos/proof_provenance.py", ROOT / "scripts/macos/env.sh",
             ROOT / "scripts/macos/check-source.py"]
    state = {"kind": kind, "pinned_engine_revision": PIN}
    if kind == "hybrid":
        if engine is None:
            raise RuntimeError("hybrid provenance requires the exact local engine checkout")
        engine = engine.resolve()
        def git(*args):
            return subprocess.check_output(["git", "-C", str(engine), *args])
        if git("ls-files", "--others", "--exclude-standard", "-z"):
            raise RuntimeError("stage new engine files before building so the source diff records them")
        state.update(engine_path=str(engine), engine_head=git("rev-parse", "HEAD").decode().strip(),
                     engine_working_diff_sha256=hashlib.sha256(git("diff", "HEAD", "--binary")).hexdigest())
        files += [ROOT / "tools/macos-hybrid/Cargo.toml", ROOT / "tools/macos-hybrid/Cargo.lock",
                  ROOT / "tools/macos-proof/src/main.rs", BASE / "hybrid-engine.toml",
                  ROOT / "scripts/macos/build-hybrid.sh", ROOT / "scripts/macos/local-engine.py"]
    elif kind == "verifier":
        # These are the isolated, copied inputs actually compiled without local overrides.
        files += [BASE / "unchanged-verifier/Cargo.toml", BASE / "unchanged-verifier/Cargo.lock",
                  BASE / "unchanged-verifier/src/main.rs", ROOT / "tools/macos-proof/Verifier.Cargo.lock",
                  ROOT / "scripts/macos/build-verifier.sh"]
    else:
        raise ValueError(f"unknown proof build kind: {kind}")
    state["inputs"] = {str(path.relative_to(ROOT)): sha(path) for path in files}
    return state


def build_environment():
    return {key: os.environ.get(key) for key in ENVIRONMENT}


def snapshot(kind, engine=None):
    value = {"source": source_state(kind, engine), "build_environment": build_environment()}
    (BASE / f"{kind}-build-inputs.json").write_text(json.dumps(value, indent=2) + "\n")


def seal(kind, engine=None):
    before = json.loads((BASE / f"{kind}-build-inputs.json").read_text())
    current = {"source": source_state(kind, engine), "build_environment": build_environment()}
    if current != before:
        raise RuntimeError(f"{kind} inputs changed during build; refusing provenance seal")
    binary, metadata = paths(kind)
    manifest = dict(current, binary_sha256=sha(binary), metadata_sha256=sha(metadata),
                    host_toolchain="1.93.0")
    (BASE / f"{kind}-build.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"{kind} executable sealed to exact source inputs, lock, and dependency metadata")
    return manifest


def verify_build(kind, binary=None, engine=None):
    expected_binary, metadata = paths(kind)
    binary = binary or expected_binary
    manifest = json.loads((BASE / f"{kind}-build.json").read_text())
    if source_state(kind, engine) != manifest["source"]:
        raise RuntimeError(f"{kind} source inputs changed since build; rebuild before testing")
    if sha(binary) != manifest["binary_sha256"]:
        raise RuntimeError(f"{kind} executable differs from the sealed build")
    if sha(metadata) != manifest["metadata_sha256"]:
        raise RuntimeError(f"{kind} dependency metadata differs from the sealed build")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["snapshot", "seal", "verify"])
    parser.add_argument("kind", choices=["hybrid", "verifier"])
    parser.add_argument("--engine", type=Path)
    args = parser.parse_args()
    if (args.kind == "hybrid") != (args.engine is not None):
        parser.error("--engine is required exactly for hybrid builds")
    if args.action == "snapshot":
        snapshot(args.kind, args.engine)
    elif args.action == "seal":
        seal(args.kind, args.engine)
    else:
        print(json.dumps(verify_build(args.kind, engine=args.engine), indent=2))


if __name__ == "__main__":
    main()
