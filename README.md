# sp1-verifier

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/zkVerify/sp1-verifier/blob/main/LICENSE-APACHE2)

This project implements a `no_std` compatible verifier for [SP1](https://github.com/succinctlabs/sp1) proofs.
The `sp1-zkv-verifier` crate is used inside [zkVerify](https://github.com/zkVerify/zkVerify) runtime to implement a verification pallet for SP1 proofs.

## Usage

To use `sp1-zkv-verifier` in your project, add it as a dependency in your `Cargo.toml`.

```toml
[dependencies]
sp1-zkv-verifier = { git = "https://github.com/zkVerify/sp1-verifier.git" }
```

Then, you can use the [`sp1_zkv_verifier::verify`](sp1-zkv-verifier/src/lib.rs) function to verify SP1 shrink proofs.

## Proof generation

This verifier only supports shrink proofs. The utility crate `sp1_zkv_sdk` provides utilities for correctly shrinking SP1 proofs. The following code snippet shows the full workflow.

```rust
use sp1_sdk::{Prover, ProverClient, SP1Stdin, include_elf};
use sp1_zkv_sdk::*;

const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci-program");

fn main() {
    // Generate SP1 compressed proof with SP1 sdk
    let mut stdin = SP1Stdin::new();
    let n = 100u32;
    stdin.write(&n);

    let prover = ProverClient::builder().cpu().build();
    let (pk, vk) = prover.setup(SP1_ELF);

    let proof = prover.prove(&pk, &stdin).compressed().run().unwrap();
    prover.verify(&proof, &vk).unwrap();

    // Convert proof and vk into a zkVerify-compatible proof
    let zkv_proof = prover
        .convert_proof_to_zkv(proof, Default::default())
        .unwrap();
    let vkey_hash = vk.convert_to_zkv();

    sp1_zkv_sdk::verify(&zkv_proof, &vkey_hash).unwrap();
}
```

## License

This project is licensed under the Apache 2.0 License.
