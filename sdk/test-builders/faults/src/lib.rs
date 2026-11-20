//! A builder that fails on purpose, for the runner's tests. `builderParams[0]` picks the fault:
//! 1 panics, 2 allocates until memory runs out, anything else returns `Ok`.

use hemiprove_builder_sdk::{self as sdk, Error};

sdk::entry!(build);

fn build() -> Result<(), Error> {
    let ctx = sdk::context()?;
    match ctx.builder_params.first() {
        Some(1) => panic!("faults: asked to panic"),
        Some(2) => {
            let mut hoard: Vec<Vec<u8>> = Vec::new();
            loop {
                hoard.push(vec![1u8; 1 << 20]);
                sdk::log(&format!("faults: {} MiB\n", hoard.len()));
            }
        }
        _ => Ok(()),
    }
}
