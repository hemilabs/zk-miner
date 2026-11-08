#!/usr/bin/env python3
"""Check seal encoding against independently verified, archived SDK output."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("measure_wrap", Path(__file__).with_name("measure-wrap.py"))
wrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wrap)
build_spec = importlib.util.spec_from_file_location("build_wrap", Path(__file__).with_name("build-arm64-wrap.py"))
build = importlib.util.module_from_spec(build_spec)
build_spec.loader.exec_module(build)

# The pinned SDK serialized this proof during independently verified run
# 08b5cca54b024b9ca9d3400f41b23b1b. The expected digest comes from that run's
# SDK-produced seal.bin, not from this Python encoder.
GOLDEN = json.loads('''{
  "pi_a": ["18891865034416642139214369072792914146151503999900790720754857469796894807598", "3432240135548747223319715026372471961778027703357916196407110377817390732333", "1"],
  "pi_b": [["10418159155442148839027051334663254678199000972796152932122877245306648822277", "7535284954573748102257650996914335797143809706326267495592253509060424505487"], ["6468753496562756394870025104887868791193744866202979294195985440530924345075", "8809884856654045910947048087764059392853038961160503374936563344730879577631"], ["1", "0"]],
  "pi_c": ["1920822623853440690170424074412328380375902172877966706330767371743111769625", "5420513118911315350501946655477419220593683966788259131538761417309552560797", "1"],
  "protocol": "groth16", "curve": "bn254"
}''')


class SealEncodingTests(unittest.TestCase):
    def test_matches_pinned_sdk_seal(self):
        seal = wrap.proof_seal(GOLDEN)
        self.assertEqual(len(seal), 256)
        self.assertEqual(hashlib.sha256(seal).hexdigest(),
                         "604bacb634e9e9cf1494e49eb62b7402a92b3a6354f90f99ba592321f41b378d")

    def test_rejects_wrong_curve_or_protocol(self):
        for key, value in (("curve", "bls12-381"), ("protocol", "plonk")):
            proof = copy.deepcopy(GOLDEN)
            proof[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                wrap.proof_seal(proof)


    def test_rejects_malformed_or_non_affine_proof(self):
        for key, value in (("pi_a", ["1"]), ("pi_c", ["1", "2", "2"]),
                           ("pi_b", [["1", "2"], ["3"], ["1", "0"]]),
                           ("pi_b", [["1", "2"], ["3", "4"], ["0", "1"]])):
            proof = copy.deepcopy(GOLDEN)
            proof[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                wrap.proof_seal(proof)

    def test_rejects_invalid_coordinate_encoding(self):
        for value in ("-1", "0x01", "1.0", "١", "", 1, str(1 << 256)):
            proof = copy.deepcopy(GOLDEN)
            proof["pi_a"][0] = value
            with self.subTest(value=value), self.assertRaises((ValueError, OverflowError)):
                wrap.proof_seal(proof)


class CircuitIdentityTests(unittest.TestCase):
    def test_materialized_circuit_must_match_original_lfs_object(self):
        data = b"pragma circom 2.0.4;\n"
        digest = hashlib.sha256(data).hexdigest()
        pointer = f"version https://git-lfs.github.com/spec/v1\noid sha256:{digest}\nsize {len(data)}\n".encode()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            circuit = root / "context/groth16/stark_verify.circom"
            circuit.parent.mkdir(parents=True)
            with patch.object(build.subprocess, "check_output", return_value=pointer):
                circuit.write_bytes(data)
                self.assertEqual(build.materialize_circuit(root, root / "context", root / "cache")["sha256"], digest)
                circuit.write_bytes(data.replace(b"2.0.4", b"2.0.5"))
                with self.assertRaisesRegex(RuntimeError, "materialized circuit differs"):
                    build.materialize_circuit(root, root / "context", root / "cache")
                circuit.write_bytes(pointer.replace(digest.encode(), b"0" * 64))
                with self.assertRaisesRegex(RuntimeError, "LFS pointer differs"):
                    build.materialize_circuit(root, root / "context", root / "cache")


if __name__ == "__main__":
    unittest.main()
