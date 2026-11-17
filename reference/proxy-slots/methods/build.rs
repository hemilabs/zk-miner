fn main() {
    // The guests named in [package.metadata.risc0], built for riscv32im-risc0-zkvm-elf with the
    // risc0 toolchain (rzup), each from its own workspace and lockfile.
    risc0_build::embed_methods();
}
