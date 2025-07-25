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

use core::borrow::Borrow;
use p3_baby_bear::BabyBear;
use p3_field::AbstractField;
use rstest::{fixture, rstest};
use sp1_recursion_core_no_std::air::RecursionPublicValues;
use sp1_zkv_verifier::Proof;
use std::fs::File;

#[fixture]
fn valid_proof() -> Proof {
    bincode::serde::decode_from_std_read(
        &mut File::open("resources/proof.bin").unwrap(),
        bincode::config::legacy(),
    )
    .unwrap()
}

#[fixture]
fn valid_vk_hash() -> [u8; 32] {
    hex::decode("45946758049372c74bceb6ba6526a9661b1915a3403125e470d5ff7f6c15c0dd")
        .unwrap()
        .try_into()
        .unwrap()
}

#[fixture]
fn valid_inputs() -> Vec<u8> {
    hex::decode("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9").unwrap()
}

#[fixture]
fn invalid_vk_hash(mut valid_vk_hash: [u8; 32]) -> [u8; 32] {
    valid_vk_hash[0] ^= 1;
    valid_vk_hash
}

#[fixture]
fn invalid_inputs(mut valid_inputs: Vec<u8>) -> Vec<u8> {
    valid_inputs[0] ^= 1;
    valid_inputs
}

#[fixture]
fn proof_with_invalid_fri_proof(mut valid_proof: Proof) -> Proof {
    valid_proof.shard_proof.opening_proof.fri_proof.query_proofs[0].commit_phase_openings[0]
        .sibling_value = Default::default();
    valid_proof
}

#[fixture]
fn proof_with_invalid_recursion_vk_root(mut valid_proof: Proof) -> Proof {
    let public_values: &RecursionPublicValues<_> =
        valid_proof.shard_proof.public_values.as_slice().borrow();
    let mut public_values = public_values.clone();
    public_values.vk_root = [Default::default(); 8];
    valid_proof.shard_proof.public_values = public_values.as_array().into();
    valid_proof
}

#[fixture]
fn proof_incomplete(mut valid_proof: Proof) -> Proof {
    let public_values: &RecursionPublicValues<_> =
        valid_proof.shard_proof.public_values.as_slice().borrow();
    let mut public_values = public_values.clone();
    public_values.is_complete = BabyBear::zero();
    valid_proof.shard_proof.public_values = public_values.as_array().into();
    valid_proof
}

#[fixture]
fn proof_with_invalid_digest(mut valid_proof: Proof) -> Proof {
    let public_values: &RecursionPublicValues<_> =
        valid_proof.shard_proof.public_values.as_slice().borrow();
    let mut public_values = public_values.clone();
    public_values.digest = [BabyBear::zero(); 8];
    valid_proof.shard_proof.public_values = public_values.as_array().into();
    valid_proof
}

#[fixture]
fn proof_with_invalid_recursion_vk_merkle_proof(mut valid_proof: Proof) -> Proof {
    valid_proof.vk_merkle_proof.path[1] = [BabyBear::zero(); 8];
    valid_proof
}

mod verifier_should_accept_if {
    use super::*;

    #[rstest]
    fn proof_vk_and_inputs_are_valid(
        valid_proof: Proof,
        valid_vk_hash: [u8; 32],
        valid_inputs: Vec<u8>,
    ) {
        assert!(sp1_zkv_verifier::verify(&valid_vk_hash, &valid_proof, &valid_inputs).is_ok());
    }
}

mod verifier_should_reject_if {
    use super::*;

    #[rstest]
    fn vk_hash_is_invalid(valid_proof: Proof, invalid_vk_hash: [u8; 32], valid_inputs: Vec<u8>) {
        assert!(sp1_zkv_verifier::verify(&invalid_vk_hash, &valid_proof, &valid_inputs).is_err());
    }

    #[rstest]
    fn proof_is_invalid(
        proof_with_invalid_fri_proof: Proof,
        valid_vk_hash: [u8; 32],
        valid_inputs: Vec<u8>,
    ) {
        assert!(
            sp1_zkv_verifier::verify(&valid_vk_hash, &proof_with_invalid_fri_proof, &valid_inputs)
                .is_err()
        );
    }

    #[rstest]
    fn proof_has_invalid_recursion_vk_root(
        proof_with_invalid_recursion_vk_root: Proof,
        valid_vk_hash: [u8; 32],
        valid_inputs: Vec<u8>,
    ) {
        assert!(
            sp1_zkv_verifier::verify(
                &valid_vk_hash,
                &proof_with_invalid_recursion_vk_root,
                &valid_inputs
            )
            .is_err()
        );
    }

    #[rstest]
    fn proof_is_incomplete(
        proof_incomplete: Proof,
        valid_vk_hash: [u8; 32],
        valid_inputs: Vec<u8>,
    ) {
        assert!(
            sp1_zkv_verifier::verify(&valid_vk_hash, &proof_incomplete, &valid_inputs).is_err()
        );
    }

    #[rstest]
    fn proof_has_invalid_public_value_digest(
        proof_with_invalid_digest: Proof,
        valid_vk_hash: [u8; 32],
        valid_inputs: Vec<u8>,
    ) {
        assert!(
            sp1_zkv_verifier::verify(&valid_vk_hash, &proof_with_invalid_digest, &valid_inputs)
                .is_err()
        );
    }

    #[rstest]
    fn proof_has_invalid_vk_recursion_merkle_proof(
        proof_with_invalid_recursion_vk_merkle_proof: Proof,
        valid_vk_hash: [u8; 32],
        valid_inputs: Vec<u8>,
    ) {
        assert!(
            sp1_zkv_verifier::verify(
                &valid_vk_hash,
                &proof_with_invalid_recursion_vk_merkle_proof,
                &valid_inputs
            )
            .is_err()
        );
    }

    #[rstest]
    fn inputs_are_invalid(valid_proof: Proof, valid_vk_hash: [u8; 32], invalid_inputs: Vec<u8>) {
        assert!(sp1_zkv_verifier::verify(&valid_vk_hash, &valid_proof, &invalid_inputs).is_err());
    }
}
