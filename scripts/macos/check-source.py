#!/usr/bin/env python3
"""Check cargo metadata proves the intended engine and explicitly selected feature closure."""
import argparse
import json
from pathlib import Path

PIN = "f8dcbdf8124a3f1528146bb01d539c55545cbb3d"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("metadata", type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--engine", type=Path)
    group.add_argument("--unchanged-verifier", action="store_true")
    parser.add_argument("--metal-runtime", action="store_true", help="allow the explicit experimental runtime Metal HAL only with --engine")
    parser.add_argument("--metal-hybrid", action="store_true", help="require the segment hybrid feature chain; implies --metal-runtime")
    parser.add_argument("--metal-recursion", action="store_true", help="require Poseidon2 recursion Metal; implies --metal-runtime")
    parser.add_argument("--metal-rv32im", action="store_true", help="require shared-buffer RV32IM Metal; implies --metal-runtime")
    args = parser.parse_args()
    args.metal_runtime = args.metal_runtime or args.metal_hybrid or args.metal_recursion or args.metal_rv32im
    if args.metal_runtime and not args.engine:
        parser.error("--metal-runtime requires a local --engine")
    observed_runtime = False
    observed_hybrid = set()
    observed_recursion = set()
    observed_rv32im = set()
    metadata = json.loads(args.metadata.read_text())
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    count = 0
    for package in metadata["packages"]:
        if package["name"].startswith("risc0-") or package["name"] == "rzup":
            count += 1
            if args.engine:
                if package["source"] is not None or not Path(package["manifest_path"]).is_relative_to(args.engine.resolve()):
                    parser.error(f"non-local engine crate: {package}")
            elif package["source"] != f"git+https://github.com/hemilabs/risc0?rev=f8dcbdf8#{PIN}":
                parser.error(f"verifier source is not the unchanged pinned Git revision: {package}")
            features = set(nodes[package["id"]]["features"])
            prohibited = {"cuda", "rocm", "intel", "metal", "bonsai", "metal-hybrid", "metal-recursion", "metal-rv32im"}
            if args.metal_rv32im:
                prohibited.remove("metal-rv32im")
                if (package["name"] == "risc0-zkvm" and "metal-rv32im" in features) or (package["name"] == "risc0-circuit-rv32im" and "metal" in features):
                    observed_rv32im.add(package["name"])
            if args.metal_recursion:
                prohibited.remove("metal-recursion")
                if (package["name"] == "risc0-zkvm" and "metal-recursion" in features) or (package["name"] == "risc0-circuit-recursion" and "metal" in features):
                    observed_recursion.add(package["name"])
            if args.metal_hybrid:
                prohibited.remove("metal-hybrid")
                if "metal-hybrid" in features:
                    observed_hybrid.add(package["name"])
            if args.metal_runtime:
                prohibited.remove("metal")
                if package["name"] == "risc0-zkp" and "metal-runtime" in features:
                    observed_runtime = True
            else:
                prohibited.add("metal-runtime")
            if args.unchanged_verifier:
                prohibited |= {"prove", "client"}
            if features & prohibited:
                parser.error(f"unexpected features in {package['name']}: {features & prohibited}")
            print(package["name"], package["version"], sorted(features))
    if args.metal_runtime and not observed_runtime:
        parser.error("runtime Metal HAL was requested but not resolved")
    if args.metal_hybrid and not {"risc0-zkvm", "risc0-circuit-rv32im"} <= observed_hybrid:
        parser.error("hybrid segment proving requires metal-hybrid in both risc0-zkvm and risc0-circuit-rv32im")
    if args.metal_recursion and observed_recursion != {"risc0-zkvm", "risc0-circuit-recursion"}:
        parser.error("recursion Metal requires metal-recursion in zkvm and metal in the recursion circuit")
    if args.metal_rv32im and observed_rv32im != {"risc0-zkvm", "risc0-circuit-rv32im"}:
        parser.error("RV32IM Metal requires metal-rv32im in zkvm and metal in the RV32IM circuit")
    if not count:
        parser.error("no engine packages found")
    print(f"verified source and feature closure of {count} engine packages")

if __name__ == "__main__":
    main()
