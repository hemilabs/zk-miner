//! A builder that writes its `builderParams` verbatim as `W`, for the miner's pre-claim pipeline
//! tests: the requester chooses the guest's input in the envelope (for the risc0 fibonacci guest,
//! `n` as 4 little-endian bytes), and the whole pipeline (artifact, sandboxed run, retention,
//! execute, binding, publish) runs on a builder whose output is known in advance. It fetches nothing.

use hemiprove_builder_sdk::{self as sdk, Error};

sdk::entry!(build);

fn build() -> Result<(), Error> {
    let ctx = sdk::context()?;
    sdk::write_witness(&ctx.builder_params).map_err(|_| Error::Other("W is over maxWitnessBytes"))?;
    sdk::log(&format!("params-echo: {} bytes\n", ctx.builder_params.len()));
    Ok(())
}
