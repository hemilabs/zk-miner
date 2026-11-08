#!/usr/bin/env python3
"""Build the native helper from verified original inputs, without changing system tools."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
from proof_provenance import PIN, ROOT, sha

BASE = ROOT / "target/macos/native-wrap"
ARCHIVE = "4b4f2b2fb8380369ed14f0dc48380a1bbcbc82c7d553f1888b47d0a9f8e72e4d"
GRAPH = "51020d6fd9ded9627ed08044fb428bca46ee2bfcc90f5819469601564050315f"
ZKEY_GZIP = "69c6056451ea814b37e30ccbc44639dbaafef73540cbfbff6ec7e68e2d325735"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--component", type=Path, default=BASE / "downloads/risc0-groth16-0.1.0.tar.xz")
    parser.add_argument("--zkey-gzip", type=Path, default=BASE / "downloads/stark_verify_final.zkey.gz")
    parser.add_argument("--r1cs", type=Path, default=BASE / "assets/stark_verify.r1cs")
    args = parser.parse_args()
    subprocess.run(["git", "-C", str(args.engine), "merge-base", "--is-ancestor", PIN, "HEAD"], check=True)
    if sha(args.component) != ARCHIVE or sha(args.zkey_gzip) != ZKEY_GZIP:
        raise RuntimeError("component archive or original zkey checksum mismatch")
    assets = BASE / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    with tarfile.open(args.component, "r:xz") as archive:
        for member in archive:
            if member.name in ("stark_verify_graph.bin", "stark_verify_final.zkey"):
                if not member.isfile():
                    raise RuntimeError("component artifact is not a regular file")
                with archive.extractfile(member) as source, (assets / member.name).open("wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
    if sha(assets / "stark_verify_graph.bin") != GRAPH:
        raise RuntimeError("unexpected witness graph")
    with gzip.open(args.zkey_gzip, "rb") as file:
        if hashlib.file_digest(file, "sha256").hexdigest() != sha(assets / "stark_verify_final.zkey"):
            raise RuntimeError("component zkey differs from the original checksum-pinned key")
    if args.r1cs.resolve() != (assets / "stark_verify.r1cs").resolve():
        shutil.copyfile(args.r1cs, assets / "stark_verify.r1cs")
    # The verified ARM64 circuit conversion establishes this R1CS identity.
    if sha(assets / "stark_verify.r1cs") != "84d3c34b7c0eb55ad1b16b24f75e0b9de307f7b74089ea4a20a998390ee24178":
        raise RuntimeError("circuit differs from the original verified build")
    source = BASE / "go-source"
    shutil.copytree(args.engine / "groth16_proof/circom-compat", source, dirs_exist_ok=True)
    env = dict(os.environ, GOCACHE=str(BASE / "go-cache"), GOMODCACHE=str(BASE / "go-modules"),
               CGO_ENABLED="0", GOOS="darwin", GOARCH="arm64", GOTOOLCHAIN="local")
    for name in ("prover", "converter"):
        subprocess.run(["go", "build", "-mod=readonly", "-o", str(BASE / name), f"./cmd/{name}"],
                       cwd=source, env=env, check=True)
    subprocess.run([str(BASE / "converter"), "--dump", str(assets / "stark_verify.r1cs"),
                    str(assets / "stark_verify_final.zkey")], check=True)
    shutil.copyfile(BASE / "prover", assets / "prover")
    (assets / "prover").chmod(0o755)
    files = {name: sha(assets / name) for name in (
        "prover", "stark_verify.cs", "stark_verify_final.pk.dmp", "stark_verify_graph.bin")}
    (assets / "manifest.json").write_text(json.dumps({"schema_version": 1, "files": files}, indent=2) + "\n")
    record = {"schema_version": 1, "component_sha256": ARCHIVE, "zkey_gzip_sha256": ZKEY_GZIP,
              "r1cs_sha256": sha(assets / "stark_verify.r1cs"), "files": files,
              "go_version": subprocess.check_output(["go", "version"], text=True).strip(),
              "go_sources": {str(p.relative_to(source)): sha(p) for p in sorted(source.rglob("*")) if p.is_file()},
              "engine_head": subprocess.check_output(["git", "-C", str(args.engine), "rev-parse", "HEAD"], text=True).strip()}
    (BASE / "build.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(files, indent=2))


if __name__ == "__main__":
    main()
