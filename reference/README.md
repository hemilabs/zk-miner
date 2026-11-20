# Reference code for witness-construction jobs

What zkminer `docs/witness-construction-jobs.md` §21.1 items 2, 4 and 5 deliver for requesters: a
guest library, a worked statement with its guest and builder, and the tooling hooks to attack a
witness.

| path | what |
|---|---|
| [`eth-prelude/`](eth-prelude/README.md) | `hemiprove-eth-prelude`: strict RLP, headers, Merkle-Patricia proofs, accounts, storage, receipts, transactions, anchors, the `Pinned`/`Authenticated` guards, and the scheme-1 (`eth-block`) witness format with its structural mutations. **Not audited**: no mainnet serving until it is (§21.1 item 4). |
| [`proxy-slots/`](proxy-slots/README.md) | plan §12's statement, its risc0 guest, the guest lints, and the executor and end-to-end tests. |
| [`../sdk/examples/proxy-slots/`](../sdk/examples/proxy-slots/README.md) | plan §12's builder (type 1, wasm32). |

**Trust, in one paragraph.** A requester trusts the binding, the guest (by image id) and the
prelude it links; never the builder, the RPC nodes or the prover. The binding pins the journal
header (the question); the guest proves the outputs (the answer) from a witness it re-validates
against the pinned values, using only values the prelude verified. A requester must audit the
guest, the prelude version it links, the image id's reproducible build, and its own parameters
(above all that a pinned block hash is canonical when submitted). The guards make an unverified
value unusable by accident, and the mutation tooling (`scheme1::Witness::standard_mutations`,
`judge`) checks that no structural change to a witness changes an answer under the same header.

The crates sit in the zkminer workspace (the guest and the lint control in workspaces of their own,
as risc0 guests are built here); the SDK workspace reaches them through its `reference` symlink.
