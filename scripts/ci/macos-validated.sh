# What the macOS beta kit's GPU code was validated with (B9-PKG, B9-M26: R17 IR scan, run_stress.sh,
# the risc0 Metal unit suites, the stock 3.1.0 verifier matrix at default/8/4 GiB, the A/B and full
# benchmarks). Sourced by assemble-macos.sh and check-macos-release.sh, which refuse a kit outside it
# unless the opt-in named below is set. Change these only with a new validation (and its note).
#
# The Metal compiler: Metal Toolchain 27B47 (Xcode 27.2). Every metallib carries the first line of
# its compiler's `metal --version` in its AIR, so the kit's check reads it from the worker itself.
# Opt-in for another compiler: METAL_COMPILER_UNVALIDATED=1.
VALIDATED_METAL_COMPILER='Apple metal version 32023.922 (metalfe-32023.922.4)'
# The macOS major versions whose offline (AOT) archive sets were validated (on macOS 27.2.1, M5 Max,
# applegpu_g17s). A macOS 27 runtime opens a macos26 set renamed to its key but takes no pipeline
# from it, so a macos26 set could not be validated here (B9-M26 note). Opt-in for another key:
# AOT_ALLOW_UNVALIDATED_OS=1 (assemble-macos.sh then records it in BUILDINFO aot_os_unvalidated).
VALIDATED_AOT_OS_MAJORS='27'
