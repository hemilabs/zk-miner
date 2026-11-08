//! Installed as an integration test in a frozen engine snapshot by test-metal-buffers.py.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]
use risc0_zkp::{
    core::{digest::Digest, hash::poseidon2::Poseidon2HashSuite},
    field::baby_bear::{BabyBear, BabyBearElem},
    hal::{cpu::CpuHal, metal::MetalHalPoseidon2, Buffer, Hal},
};

#[test]
fn shared_buffers_preserve_offsets_and_cpu_writes_across_gpu_reuse() {
    metal::objc::rc::autoreleasepool(|| {
        let cpu = CpuHal::<BabyBear>::new(Poseidon2HashSuite::new_suite());
        let gpu = MetalHalPoseidon2::new();
        let empty = gpu.alloc_elem("empty", 0);
        let before = gpu.completed_dispatches();
        gpu.eltwise_add_elem(&empty, &empty, &empty);
        assert!(empty.to_vec().is_empty());
        assert_eq!(gpu.completed_dispatches(), before);
        let empty_digest = gpu.alloc_digest("empty_digest", 0);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            gpu.hash_rows(&empty_digest, &empty)
        }))
        .is_err());
        assert_eq!(gpu.completed_dispatches(), before);
        let empty_cpu = cpu.alloc_elem("empty_reference", 0);
        let empty_cpu_digest = cpu.alloc_digest("empty_reference_digest", 0);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            cpu.hash_rows(&empty_cpu_digest, &empty_cpu)
        }))
        .is_err());

        let element_sentinel = BabyBearElem::new(42);
        let digest_sentinel = Digest::new([42; 8]);
        for (rows, columns) in [(1, 0), (1, 1), (3, 15), (32, 16), (257, 17), (2049, 33)] {
            let count = rows * columns;
            let matrix_storage = gpu.copy_from_elem("matrix", &vec![element_sentinel; count + 6]);
            let matrix = matrix_storage.slice(3, count);
            let output_storage = gpu.copy_from_digest("output", &vec![digest_sentinel; rows + 6]);
            let output = output_storage.slice(3, rows);
            let reference_matrix = cpu.copy_from_elem("reference", &vec![element_sentinel; count]);
            let reference = cpu.alloc_digest("reference_output", rows);
            for pass in 0..6 {
                // Reuse the same allocations, changing CPU-written input after
                // the preceding GPU command and host read have completed.
                let write = |values: &mut [BabyBearElem]| {
                    for (i, value) in values.iter_mut().enumerate() {
                        *value = BabyBearElem::new(((i * 7919 + pass * 104729) % 1_000_000) as u32);
                    }
                };
                matrix.view_mut(write);
                reference_matrix.view_mut(write);
                output.view_mut(|values| values.fill(digest_sentinel));
                gpu.hash_rows(&output, &matrix);
                cpu.hash_rows(&reference, &reference_matrix);
                assert_eq!(
                    output.to_vec(),
                    reference.to_vec(),
                    "shape {rows}x{columns}, pass {pass}"
                );
                let full = output_storage.to_vec();
                assert!(full[..3]
                    .iter()
                    .chain(&full[full.len() - 3..])
                    .all(|v| *v == digest_sentinel));
                let full = matrix_storage.to_vec();
                assert!(full[..3]
                    .iter()
                    .chain(&full[full.len() - 3..])
                    .all(|v| *v == element_sentinel));
            }
        }
        assert_eq!(gpu.completed_dispatches() - before, 36);
    });
}
