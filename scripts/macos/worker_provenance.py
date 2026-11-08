#!/usr/bin/env python3
"""Bind native worker builds to reviewed engine, workspace, fixture, and lock inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "target/macos"
PIN = "f8dcbdf8124a3f1528146bb01d539c55545cbb3d"
ENVIRONMENT = (
    "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "DEVELOPER_DIR", "TOOLCHAINS", "SDKROOT",
    "CC", "CXX", "CFLAGS", "CXXFLAGS", "AR", "RUSTC", "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_JOBS", "CARGO_HOME", "RUSTUP_HOME",
    "RISC0_HOME", "ZKMINER_RISC0_GUEST_DIR", "PROTOC",
)


def sha(path):
    with Path(path).open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def profile(kind):
    if kind not in ("cpu", "metal", "native", "native-recursion-metal", "native-rv32im-metal"):
        raise ValueError("worker build kind must be cpu or metal")
    return {"cpu": "worker", "metal": "worker-metal", "native": "worker-native",
            "native-recursion-metal": "worker-native-recursion-metal", "native-rv32im-metal":"worker-native-rv32im-metal"}[kind]


def paths(kind):
    name = profile(kind)
    return {
        "binary": BASE / name / "release/zkminer-prove-risc0",
        "metadata": BASE / f"{name}-metadata.json",
        "local_lock": BASE / f"{name}-local-Cargo.lock",
        "manifest": BASE / f"{name}-build.json",
        "snapshot": BASE / f"{name}-build-inputs.json",
    }


def source_state(kind, engine, config):
    engine, config = Path(engine).resolve(), Path(config).resolve()
    def git(*args):
        return subprocess.check_output(["git", "-C", str(engine), *args])
    untracked = git("ls-files", "--others", "--exclude-standard", "-z").decode().split("\0")
    untracked_hashes = {name: sha(engine / name) for name in untracked if name}
    files = [ROOT / "Cargo.toml", ROOT / "Cargo.lock",
             ROOT / "scripts/macos/build-worker.py", ROOT / "scripts/macos/worker_provenance.py",
             ROOT / "scripts/macos/local-engine.py", ROOT / "scripts/macos/check-source.py",
             ROOT / "scripts/macos/env.sh", config]
    for crate in ("zkminer-prove-risc0", "zkminer-prover-protocol"):
        directory = ROOT / "crates" / crate
        files += [directory / "Cargo.toml"]
        files += sorted((directory / "src").rglob("*.rs"))
        if (directory / "build.rs").is_file():
            files.append(directory / "build.rs")
    for relative in ("rust-toolchain", "rust-toolchain.toml", ".cargo/config", ".cargo/config.toml"):
        if (ROOT / relative).is_file():
            files.append(ROOT / relative)
    guests = BASE / "guest-build/riscv32im-risc0-zkvm-elf/release"
    files += [guests / f"{name}.bin" for name in ("fibonacci", "sha256-chain")]
    return {
        "kind": kind, "pinned_engine_revision": PIN, "engine_path": str(engine),
        "engine_head": git("rev-parse", "HEAD").decode().strip(),
        "engine_working_diff_sha256": hashlib.sha256(git("diff", "HEAD", "--binary")).hexdigest(),
        "engine_untracked_files": untracked_hashes,
        "config_path": str(config),
        "inputs": {str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path): sha(path)
                   for path in sorted(set(files))},
    }


def snapshot(kind, engine, config, env=None):
    env = os.environ if env is None else env
    value = {"source": source_state(kind, engine, config),
             "build_environment": {key: env.get(key) for key in ENVIRONMENT}}
    paths(kind)["snapshot"].write_text(json.dumps(value, indent=2) + "\n")


def seal(kind, engine, config, env=None):
    env = os.environ if env is None else env
    artifacts = paths(kind)
    before = json.loads(artifacts["snapshot"].read_text())
    current = {"source": source_state(kind, engine, config),
               "build_environment": {key: env.get(key) for key in ENVIRONMENT}}
    if current != before:
        raise RuntimeError("worker inputs changed during build; refusing provenance seal")
    manifest = dict(current, binary_sha256=sha(artifacts["binary"]),
                    metadata_sha256=sha(artifacts["metadata"]),
                    local_lock_sha256=sha(artifacts["local_lock"]), host_toolchain="1.93.0")
    artifacts["manifest"].write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"{profile(kind)} sealed to exact source, fixtures, binary, metadata and local lock")
    return manifest


def verify_build(kind, engine, binary=None):
    artifacts = paths(kind)
    manifest = json.loads(artifacts["manifest"].read_text())
    config = Path(manifest["source"]["config_path"])
    if source_state(kind, engine, config) != manifest["source"]:
        raise RuntimeError("worker source inputs changed since build; rebuild before testing")
    for name, path in (("binary", binary or artifacts["binary"]),
                       ("metadata", artifacts["metadata"]), ("local_lock", artifacts["local_lock"])):
        if sha(path) != manifest[f"{name}_sha256"]:
            raise RuntimeError(f"worker {name} differs from the sealed build")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=["cpu", "metal", "native", "native-recursion-metal", "native-rv32im-metal"])
    parser.add_argument("--engine", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify_build(args.kind, args.engine), indent=2))


if __name__ == "__main__":
    main()
