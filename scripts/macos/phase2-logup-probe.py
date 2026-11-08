#!/usr/bin/env python3
"""Make a timing-only RV32IM Metal shader with the LogUp tail removed.

This diagnostic must never be passed to a worker or used to prove. It cuts the
generated v2_3 tail at the same x1102 boundary used by evalfast's accfirst_cuda
pass, leaving the main-chain result and deleting the LogUp continuation.
"""

import argparse
import hashlib
import json
from pathlib import Path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reference-output", type=Path, required=True)
    args = parser.parse_args()
    source = args.input.read_text()
    metadata = json.loads(args.input.with_suffix(".json").read_text())
    assert metadata["split_chains"] and not metadata.get("fast_ext", False) and not metadata.get("fast_fp", False)
    start_marker = '#line 1 "rv32im_v2_3_tail.msl"\n'
    end_marker = '#line 1 "rv32im_v2_3.msl"\n'
    assert source.count(start_marker) == source.count(end_marker) == 1
    start = source.index(start_marker)
    end = source.index(end_marker, start)
    body = source[start:end]
    anchor = '  FpExt x1102 = x1090 + poly_mix[437] * x1101;\n'
    assert body.count(anchor) == 1
    assert 'rv32im_v2_2(' in body[body.index(anchor):]
    kept = body[:body.index(anchor) + len(anchor)]
    removed = body[len(kept):]
    assert removed.rstrip().endswith('return x1255;\n}')
    diagnostic = (source[:start] + kept + '  return x1102;\n}\n\n' + source[end:])
    assert diagnostic != source
    args.reference_output.parent.mkdir(parents=True, exist_ok=True)
    args.reference_output.write_text(source)
    reference_metadata = dict(metadata, timing_only=True, proof_eligible=False,
                              cpu_oracle_checked=False,
                              diagnostic_transform="unchanged tail-split/256 shader; timing-only harness")
    args.reference_output.with_suffix(".json").write_text(json.dumps(reference_metadata, indent=2) + "\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(diagnostic)
    metadata.update({
        "source_sha256": sha(diagnostic.encode()),
        "timing_only": True,
        "proof_eligible": False,
        "cpu_oracle_checked": False,
        "diagnostic_transform": "v2_3 tail returns x1102; LogUp continuation and v2_2..0 calls removed",
        "removed_tail_bytes": len(removed.encode()),
        "parent_source_sha256": sha(source.encode()),
        "diagnostic_script_sha256": sha(Path(__file__).read_bytes()),
    })
    args.output.with_suffix(".json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(args.reference_output)
    print(args.output)


if __name__ == "__main__":
    main()
