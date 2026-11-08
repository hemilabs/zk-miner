#!/usr/bin/env python3
"""Acceptance-control unit tests only: synthetic metadata is never proving evidence."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest
from unittest.mock import patch

import proof_provenance as provenance
from smoke import validate_proof_evidence


def valid_metal_report():
    segments = [{"segment_index": i, "po2": 16, "completed_dispatches": 8,
                 "fold_calls": 6, "input_digests": 256, "output_digests": 128,
                 "peak_staging_bytes": 12288, "staging_limit_bytes": 524288} for i in range(2)]
    return {"requested_mode": "metal", "proof_kind": "groth16", "stats": {"segments": 2},
            "observed_stages": {"metal_stage": {"name": "segment_poseidon2_merkle_fold",
                                 "segments": segments, "completed_dispatches": 16}}}


class StageEvidenceTests(unittest.TestCase):
    def test_accepts_complete_segment_coverage_and_cpu_without_metal(self):
        validate_proof_evidence(valid_metal_report(), "metal")
        validate_proof_evidence({"requested_mode": "cpu", "proof_kind": "groth16",
                                 "stats": {"segments": 2}}, "cpu")

    def test_rejects_incomplete_or_inconsistent_gpu_evidence(self):
        changes = [
            lambda p: p.update(proof_kind="succinct"),
            lambda p: p.update(requested_mode="cpu"),
            lambda p: p["stats"].update(segments=3),
            lambda p: p["observed_stages"].clear(),
            lambda p: p["observed_stages"]["metal_stage"].update(completed_dispatches=17),
            lambda p: p["observed_stages"]["metal_stage"]["segments"][0].update(segment_index=1),
            lambda p: p["observed_stages"]["metal_stage"]["segments"][0].update(completed_dispatches=0),
            lambda p: p["observed_stages"]["metal_stage"]["segments"][0].update(fold_calls=0),
            lambda p: p["observed_stages"]["metal_stage"]["segments"][0].update(output_digests=0),
            lambda p: p["observed_stages"]["metal_stage"]["segments"][0].update(input_digests=257),
            lambda p: p["observed_stages"]["metal_stage"]["segments"][0].update(peak_staging_bytes=524289),
            lambda p: p["observed_stages"]["metal_stage"]["segments"][0].update(staging_limit_bytes=32 * 1024**2),
        ]
        for i, change in enumerate(changes):
            with self.subTest(case=i):
                report = valid_metal_report()
                change(report)
                with self.assertRaises(RuntimeError):
                    validate_proof_evidence(report, "metal")

    def test_cpu_rejects_gpu_work(self):
        report = valid_metal_report()
        report["requested_mode"] = "cpu"
        with self.assertRaisesRegex(RuntimeError, "CPU baseline"):
            validate_proof_evidence(report, "cpu")


class BuildBindingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hemi-proof-controls-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.base = self.root / "target/macos"
        self.base.mkdir(parents=True)
        for key, value in (("ROOT", self.root), ("BASE", self.base)):
            patcher = patch.object(provenance, key, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        files = ["scripts/macos/proof_provenance.py", "scripts/macos/env.sh", "scripts/macos/check-source.py",
                 "scripts/macos/build-verifier.sh", "scripts/macos/build-hybrid.sh", "scripts/macos/local-engine.py",
                 "tools/macos-hybrid/Cargo.toml", "tools/macos-hybrid/Cargo.lock", "tools/macos-proof/src/main.rs",
                 "tools/macos-proof/Verifier.Cargo.lock",
                 "target/macos/hybrid-engine.toml", "target/macos/unchanged-verifier/Cargo.toml",
                 "target/macos/unchanged-verifier/Cargo.lock", "target/macos/unchanged-verifier/src/main.rs"]
        for name in files:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic control-test input; never built\n")
        for kind in ("hybrid", "verifier"):
            binary, metadata = provenance.paths(kind)
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(b"control-test bytes, not an executable")
            metadata.write_text("synthetic control-test metadata\n")
        self.engine = self.root / "engine"
        self.engine.mkdir()
        self.git_env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        self.git("init", "--quiet")
        (self.engine / "source.rs").write_text("// control-test source\n")
        self.git("add", "source.rs")
        self.git("-c", "user.name=Control Tests", "-c", "user.email=control-tests@example.invalid",
                 "commit", "--quiet", "--no-gpg-sign", "-m", "control-test fixture")

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.engine), *args], env=self.git_env, check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def seal(self, kind):
        engine = self.engine if kind == "hybrid" else None
        provenance.snapshot(kind, engine)
        with contextlib.redirect_stdout(io.StringIO()):
            provenance.seal(kind, engine)
        return engine

    def test_rejects_changed_binary_metadata_lock_and_source(self):
        for kind in ("hybrid", "verifier"):
            engine = self.seal(kind)
            provenance.verify_build(kind, engine=engine)
            source_paths = [self.root / path for path in provenance.source_state(kind, engine)["inputs"]]
            for path in [*provenance.paths(kind), *source_paths]:
                with self.subTest(kind=kind, changed=str(path.relative_to(self.root))):
                    original = path.read_bytes()
                    path.write_bytes(original + b"changed")
                    with self.assertRaises(RuntimeError):
                        provenance.verify_build(kind, engine=engine)
                    path.write_bytes(original)
            provenance.verify_build(kind, engine=engine)

    def test_rejects_changed_engine_diff_and_untracked_source(self):
        self.seal("hybrid")
        path = self.engine / "source.rs"
        original = path.read_text()
        path.write_text(original + "// changed\n")
        with self.assertRaisesRegex(RuntimeError, "source inputs changed"):
            provenance.verify_build("hybrid", engine=self.engine)
        path.write_text(original)
        (self.engine / "untracked.rs").write_text("// not recorded\n")
        with self.assertRaisesRegex(RuntimeError, "stage new engine files"):
            provenance.verify_build("hybrid", engine=self.engine)

    def test_refuses_source_or_build_environment_change_during_build(self):
        provenance.snapshot("verifier")
        with patch.dict(os.environ, {"RUSTFLAGS": "control-test-changed"}):
            with self.assertRaisesRegex(RuntimeError, "changed during build"):
                provenance.seal("verifier")
        path = self.base / "unchanged-verifier/src/main.rs"
        path.write_text("changed during build\n")
        with self.assertRaisesRegex(RuntimeError, "changed during build"):
            provenance.seal("verifier")


class FeatureClosureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hemi-feature-controls-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.engine = self.root / "engine"
        self.metadata = self.root / "metadata.json"
        self.packages = [{"id": name, "name": name, "version": "test", "source": None,
                          "manifest_path": str(self.engine / name / "Cargo.toml")}
                         for name in ("risc0-zkvm", "risc0-circuit-rv32im", "risc0-zkp")]
        self.nodes = [{"id": name, "features": features} for name, features in (
            ("risc0-zkvm", ["metal-hybrid", "prove"]),
            ("risc0-circuit-rv32im", ["metal-hybrid", "prove"]),
            ("risc0-zkp", ["metal-runtime", "metal", "prove"]))]

    def check(self, *args):
        self.metadata.write_text(json.dumps({"packages": self.packages, "resolve": {"nodes": self.nodes}}))
        return subprocess.run([sys.executable, str(Path(__file__).with_name("check-source.py")),
                               str(self.metadata), *args], capture_output=True, text=True)

    def test_requires_entire_hybrid_chain_and_rejects_it_in_cpu_or_primitive_mode(self):
        self.assertEqual(self.check("--engine", str(self.engine), "--metal-hybrid").returncode, 0)
        self.assertNotEqual(self.check("--engine", str(self.engine)).returncode, 0)
        self.assertNotEqual(self.check("--engine", str(self.engine), "--metal-runtime").returncode, 0)
        for node in self.nodes[:2]:
            node["features"].remove("metal-hybrid")
            self.assertNotEqual(self.check("--engine", str(self.engine), "--metal-hybrid").returncode, 0)
            node["features"].append("metal-hybrid")
        self.nodes[-1]["features"].remove("metal-runtime")
        self.assertNotEqual(self.check("--engine", str(self.engine), "--metal-hybrid").returncode, 0)

    def test_unchanged_verifier_rejects_hybrid_even_without_prove_feature(self):
        source = "git+https://github.com/hemilabs/risc0?rev=f8dcbdf8#" + provenance.PIN
        for package in self.packages:
            package["source"] = source
        for node in self.nodes:
            node["features"] = []
        self.assertEqual(self.check("--unchanged-verifier").returncode, 0)
        self.nodes[0]["features"] = ["metal-hybrid"]
        self.assertNotEqual(self.check("--unchanged-verifier").returncode, 0)


if __name__ == "__main__":
    unittest.main()
