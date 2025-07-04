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
use p3_field::PrimeField32;
use sp1_prover::components::SP1ProverComponents;
use sp1_sdk::{HashableKey, Prover, SP1ProofWithPublicValues, SP1VerifyingKey};
use sp1_stark::{SP1ProverOpts, baby_bear_poseidon2::BabyBearPoseidon2};
use thiserror::Error;

type ShardProof = sp1_stark::ShardProof<BabyBearPoseidon2>;

pub struct SP1ZkvProofWithPublicValues {
    pub proof: ShardProof,
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
        let zkv_proof = self
            .inner()
            .shrink(*compressed_proof, opts.unwrap_or_default())?
            .proof;
        Ok(SP1ZkvProofWithPublicValues {
            proof: zkv_proof,
            public_values: proof.public_values.to_vec(),
        })
    }
}

pub trait ConvertVerifyingKeyToZkv {
    fn convert_to_zkv(&self) -> [u8; 32];
}

impl ConvertVerifyingKeyToZkv for SP1VerifyingKey {
    fn convert_to_zkv(&self) -> [u8; 32] {
        self.hash_babybear()
            .iter()
            .flat_map(|el| el.as_canonical_u32().to_le_bytes())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

pub fn verify(
    proof_with_public_values: &SP1ZkvProofWithPublicValues,
    vkey: &[u8; 32],
) -> Result<()> {
    let proof = unsafe {
        std::mem::transmute::<&ShardProof, &sp1_zkv_verifier::ShardProof>(
            &proof_with_public_values.proof,
        )
    };
    sp1_zkv_verifier::verify(vkey, proof, &proof_with_public_values.public_values)?;
    Ok(())
}

#[derive(Error, Debug)]
pub enum SP1ZkvError {
    #[error("Unsupported proof format: only Compressed proofs are supported.")]
    UnsupportedProofFormat,
}
