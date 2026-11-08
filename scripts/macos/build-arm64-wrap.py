#!/usr/bin/env python3
"""Build the pinned Groth16 helper for ARM64 without changing worker selection."""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.request
import uuid

from proof_provenance import PIN, ROOT, sha


def save(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def output(command):
    return subprocess.check_output(command, text=True, timeout=60).strip()


def materialize_circuit(engine, context, cache):
    """Fetch the exact original LFS object into the build snapshot, not the checkout."""
    name = "groth16/stark_verify.circom"
    path = context / name
    with path.open("rb") as file:
        prefix = file.read(256)
    original = subprocess.check_output(["git", "-C", str(engine), "show", f"{PIN}:groth16_proof/{name}"])
    is_pointer = prefix.startswith(b"version https://git-lfs.github.com/spec/v1\n")
    if is_pointer and path.read_bytes() != original:
        raise RuntimeError("circuit LFS pointer differs from the original engine pin")
    lines = original.decode().splitlines()
    digest, size = lines[1].removeprefix("oid sha256:"), int(lines[2].removeprefix("size "))
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise RuntimeError("invalid pinned LFS digest")
    if not is_pointer:
        if path.stat().st_size != size or sha(path) != digest:
            raise RuntimeError("materialized circuit differs from the original engine pin")
        return {"path": name, "sha256": digest, "size": size, "source": "checkout"}
    # The Hemi fork does not serve this inherited LFS object. The original
    # introducing commit exists in upstream; accept only the pinned object's
    # exact size and SHA-256, never upstream HEAD's circuit contents.
    circuit_commit = output(["git", "-C", str(engine), "log", "-1", "--format=%H", PIN,
                             "--", f"groth16_proof/{name}"])
    url = f"https://media.githubusercontent.com/media/risc0/risc0/{circuit_commit}/groth16_proof/{name}"
    cache.mkdir(parents=True, exist_ok=True)
    cached = cache / digest
    if not cached.exists():
        temporary = cached.with_suffix(".download")
        count = 0
        with urllib.request.urlopen(url, timeout=60) as response, temporary.open("wb") as file:
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                if count > size:
                    raise RuntimeError("LFS response exceeds pinned size")
                file.write(chunk)
        if temporary.stat().st_size != size or sha(temporary) != digest:
            raise RuntimeError("downloaded circuit differs from pinned LFS size/hash")
        temporary.replace(cached)
    if cached.stat().st_size != size or sha(cached) != digest:
        raise RuntimeError("cached circuit differs from pinned LFS size/hash")
    shutil.copyfile(cached, path)
    return {"path": name, "url": url, "sha256": digest, "size": size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--context", default="colima-hemi-macos-cpu")
    parser.add_argument("--buildx", type=Path, help="optional project-local standalone Buildx binary")
    parser.add_argument("--timeout", type=int, default=10800)
    args = parser.parse_args()
    if args.context != "colima-hemi-macos-cpu" or not 60 <= args.timeout <= 14400:
        parser.error("use the dedicated context and a 60..14400 second timeout")
    engine = args.engine.resolve()
    subprocess.run(["git", "-C", str(engine), "merge-base", "--is-ancestor", PIN, "HEAD"], check=True)
    docker = ["docker", "--context", args.context]
    endpoint = output(docker + ["context", "inspect", args.context, "--format", "{{.Endpoints.docker.Host}}"])
    if not endpoint.startswith("unix://"):
        raise RuntimeError("a local Unix Docker socket is required")
    info = json.loads(output(docker + ["info", "--format", "{{json .}}",]))
    if info["Architecture"] not in ("aarch64", "arm64"):
        raise RuntimeError("the feasibility build requires a native ARM64 daemon")
    base = ROOT / "target/macos/arm64-wrap-builds"
    base.mkdir(parents=True, exist_ok=True)
    with (base / "active.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        build_id = uuid.uuid4().hex
        directory = base / build_id
        directory.mkdir()
        preparation_start = time.monotonic()
        preparation = {"schema_version": 1, "build_id": build_id, "status": "preparing",
                       "started_at_utc": datetime.now(timezone.utc).isoformat(),
                       "engine_path": str(engine), "context": args.context}
        save(directory / "result.json", preparation)
        shutil.copyfile(Path(__file__).resolve(), directory / "build-runner.py")
        context = directory / "context"
        try:
            shutil.copytree(engine / "groth16_proof", context,
                            ignore=shutil.ignore_patterns(".git", "target", "*.pk", "*.dmp", "*.wtns"))
            circuit = materialize_circuit(engine, context, base / "inputs")
        except BaseException as error:
            preparation.update(status="failed", phase="prepare", error=str(error),
                               preparation_seconds=time.monotonic() - preparation_start)
            save(directory / "result.json", preparation)
            raise
        hashes = {str(p.relative_to(context)): sha(p) for p in sorted(context.rglob("*")) if p.is_file()}
        tag = "zkminer/groth16-arm64:feasibility-" + build_id
        buildx = ([str(args.buildx.resolve()), "--builder", args.context] if args.buildx
                  else docker + ["buildx"])
        command = buildx + ["build", "--platform", "linux/arm64", "--load",
                            "--provenance=mode=max", "--progress=plain", "--tag", tag,
                            "--metadata-file", str(directory / "buildkit.json"),
                            "--iidfile", str(directory / "image-id.txt"),
                            "--file", str(context / "docker/prover.Dockerfile"), str(context)]
        report = {"schema_version": 1, "build_id": build_id, "status": "building",
                  "started_at_utc": preparation["started_at_utc"],
                  "preparation_seconds": time.monotonic() - preparation_start,
                  "miner_head": output(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
                  "engine_head": output(["git", "-C", str(engine), "rev-parse", "HEAD"]),
                  "engine_diff_sha256": hashlib.sha256(subprocess.check_output(
                      ["git", "-C", str(engine), "diff", "HEAD", "--binary"])).hexdigest(),
                  "source_files": hashes, "circuit_lfs": circuit, "runner_sha256": sha(directory / "build-runner.py"),
                  "buildx_sha256": sha(args.buildx.resolve()) if args.buildx else None,
                  "image_tag": tag, "platform": "linux/arm64", "context": args.context,
                  "daemon": {k: info[k] for k in ("Architecture", "NCPU", "MemTotal", "ServerVersion")},
                  "command": command, "build_timeout_seconds": args.timeout}
        save(directory / "result.json", report)
        (directory / "engine.patch").write_bytes(subprocess.check_output(
            ["git", "-C", str(engine), "diff", "HEAD", "--binary"]))
        print(directory, flush=True)
        start = time.monotonic()
        try:
            with (directory / "build.log").open("w") as log:
                env = dict(os.environ, DOCKER_CONTEXT=args.context, BUILDX_METADATA_PROVENANCE="max")
                subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT,
                               check=True, timeout=args.timeout)
            image_id = (directory / "image-id.txt").read_text().strip()
            image_info = json.loads(output(docker + ["image", "inspect", image_id]))[0]
            if (image_info["Os"], image_info["Architecture"]) != ("linux", "arm64"):
                raise RuntimeError("built image is not linux/arm64")
            save(directory / "image-inspect.json", image_info)
            report.update(status="built", image_id=image_id,
                          image_inspect_sha256=sha(directory / "image-inspect.json"))
        except BaseException as error:
            report.update(status="failed", error=str(error))
            raise
        finally:
            report["build_seconds"] = time.monotonic() - start
            save(directory / "result.json", report)


if __name__ == "__main__":
    main()
