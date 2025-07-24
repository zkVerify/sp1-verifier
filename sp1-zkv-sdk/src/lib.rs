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

use anyhow::Result;
use p3_baby_bear::BabyBear;
use serde::{Deserialize, Serialize};
use sp1_core_executor::SP1ReduceProof;
use sp1_prover::{InnerSC, components::SP1ProverComponents};
use sp1_recursion_circuit::{machine::SP1CompressWitnessValues, merkle_tree::MerkleProof};
use sp1_sdk::{Prover, SP1ProofWithPublicValues};
use sp1_stark::{SP1ProverOpts, StarkVerifyingKey, baby_bear_poseidon2::BabyBearPoseidon2};
use thiserror::Error;

type ShardProof = sp1_stark::ShardProof<BabyBearPoseidon2>;

#[derive(Clone, Serialize, Deserialize)]
pub struct Proof {
    pub shard_proof: ShardProof,
    pub vk: StarkVerifyingKey<InnerSC>,
    pub vk_merkle_proof: MerkleProof<BabyBear, BabyBearPoseidon2>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SP1ZkvProofWithPublicValues {
    pub proof: Proof,
    pub public_values: Vec<u8>,
}

pub trait ZkvProver<C> {
    fn convert_proof_to_zkv(
        &self,
        proof: SP1ProofWithPublicValues,
        opts: Option<SP1ProverOpts>,
    ) -> Result<SP1ZkvProofWithPublicValues>;
}

impl<T, C> ZkvProver<C> for T
where
    T: Prover<C>,
    C: SP1ProverComponents,
{
    fn convert_proof_to_zkv(
        &self,
        proof: SP1ProofWithPublicValues,
        opts: Option<SP1ProverOpts>,
    ) -> Result<SP1ZkvProofWithPublicValues> {
        let compressed_proof = proof
            .proof
            .try_as_compressed()
            .ok_or(SP1ZkvError::UnsupportedProofFormat)?;
        let SP1ReduceProof {
            vk,
            proof: shard_proof,
        } = self
            .inner()
            .shrink(*compressed_proof, opts.unwrap_or_default())?;
        let input = SP1CompressWitnessValues {
            vks_and_proofs: vec![(vk.clone(), shard_proof.clone())],
            is_complete: true,
        };
        let proof_with_vk_and_merkle = self.inner().make_merkle_proofs(input);
        Ok(SP1ZkvProofWithPublicValues {
            proof: Proof {
                shard_proof,
                vk,
                vk_merkle_proof: proof_with_vk_and_merkle.merkle_val.vk_merkle_proofs[0].clone(),
            },
            public_values: proof.public_values.to_vec(),
        })
    }
}

pub fn verify(
    proof_with_public_values: &SP1ZkvProofWithPublicValues,
    vkey: &[u8; 32],
) -> Result<()> {
    let proof = unsafe {
        std::mem::transmute::<&Proof, &sp1_zkv_verifier::Proof>(&proof_with_public_values.proof)
    };
    sp1_zkv_verifier::verify(vkey, proof, &proof_with_public_values.public_values)?;
    Ok(())
}

#[derive(Error, Debug)]
pub enum SP1ZkvError {
    #[error("Unsupported proof format: only Compressed proofs are supported.")]
    UnsupportedProofFormat,
}
