fn main() {
    // Compile RISC Zero guest programs when the risc0 feature is enabled.
    #[cfg(feature = "risc0")]
    {
        risc0_build::embed_methods();
    }

    // Compile SP1 guest programs when the sp1 feature is enabled.
    #[cfg(feature = "sp1")]
    {
        sp1_build::build_program("guests/sp1/fibonacci");
        sp1_build::build_program("guests/sp1/sha256-chain");
        sp1_build::build_program("guests/sp1/rv32im-torture");
        sp1_build::build_program("guests/sp1/edge-case-arith");
        sp1_build::build_program("guests/sp1/memory-stress");
        sp1_build::build_program("guests/sp1/precompile-interleave");
        sp1_build::build_program("guests/sp1/segment-boundary");
        sp1_build::build_program("guests/sp1/minimal-proof");
        sp1_build::build_program("guests/sp1/chacha-mix");
        sp1_build::build_program("guests/sp1/bigint-mul");
        sp1_build::build_program("guests/sp1/ecdsa-verify");
        sp1_build::build_program("guests/sp1/memory-merkle");
    }
}
