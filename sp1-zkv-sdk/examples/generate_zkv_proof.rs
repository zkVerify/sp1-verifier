// Copyright 2025, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use sp1_elf::SP1_ELF;
use sp1_sdk::{HashableKey, Prover, ProverClient, SP1Stdin};
use sp1_zkv_sdk::*;

fn main() {
    // Generate SP1 compressed proof with SP1 sdk
    let mut stdin = SP1Stdin::new();
    stdin.write(&b"hello world".to_vec());

    let prover = ProverClient::builder().cpu().build();
    let (pk, vk) = prover.setup(SP1_ELF);

    let proof = prover.prove(&pk, &stdin).compressed().run().unwrap();
    prover.verify(&proof, &vk).unwrap();

    // Convert proof and vk into a zkVerify-compatible proof
    let zkv_proof = prover
        .convert_proof_to_zkv(proof, Default::default())
        .unwrap();
    let vkey_hash = vk.hash_bytes();

    sp1_zkv_sdk::verify(&zkv_proof, &vkey_hash).unwrap();
}
