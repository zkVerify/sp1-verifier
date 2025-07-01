#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::borrow::Borrow;
use itertools::Itertools;
use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, Field, PrimeField32};
use p3_symmetric::CryptographicHasher;
use sha2::{Digest, Sha256};
use sp1_recursion_core_no_std::{
    air::{NUM_PV_ELMS_TO_HASH, RecursionPublicValues},
    machine::RecursionAir,
};
use sp1_stark_no_std::{
    InnerHash, MachineProof, MachineVerificationError, StarkGenericConfig,
    baby_bear_poseidon2::BabyBearPoseidon2,
};

pub use sp1_stark_no_std::{ShardProof, StarkVerifyingKey};

const SHRINK_DEGREE: usize = 3;
const DIGEST_SIZE: usize = 8;

pub type InnerSC = BabyBearPoseidon2;
pub type ShrinkAir<F> = RecursionAir<F, SHRINK_DEGREE>;

const SHRINK_VK_BYTES: &[u8] = include_bytes!("../resources/vk.bin");

fn shrink_vk() -> StarkVerifyingKey<InnerSC> {
    bincode::serde::decode_from_slice(SHRINK_VK_BYTES, bincode::config::legacy())
        .unwrap()
        .0
}

fn recursion_vk_root() -> [BabyBear; DIGEST_SIZE] {
    [
        779620665u32,
        657361014,
        1275916220,
        1016544356,
        761269804,
        102002516,
        650304731,
        1117171342,
    ]
    .map(|n| BabyBear::from_canonical_u32(n))
}

pub fn verify(
    vkey_hash: [u8; 32],
    proof: &ShardProof<InnerSC>,
    inputs: &[u8],
) -> Result<(), MachineVerificationError<InnerSC>> {
    let shrink_machine = ShrinkAir::shrink_machine(InnerSC::compressed());
    let mut challenger = shrink_machine.config().challenger();

    shrink_machine
        .verify(
            &shrink_vk(),
            &MachineProof {
                shard_proofs: vec![proof.clone()],
            },
            &mut challenger,
        )
        .unwrap();

    // Validate public values
    let public_values: &RecursionPublicValues<_> = proof.public_values.as_slice().borrow();

    let committed_value_digest_bytes: [u8; 32] = public_values
        .committed_value_digest
        .iter()
        .flat_map(|w| w.0.iter().map(|x| x.as_canonical_u32() as u8))
        .collect_vec()
        .try_into()
        .unwrap();

    let blake3_input_hash = blake3::hash(inputs);
    let sha256_input_hash = Sha256::new().chain_update(inputs).finalize();

    // Make sure the committed value digest matches the public values hash.
    // It is computationally infeasible to find two distinct inputs, one processed with
    // SHA256 and the other with Blake3, that yield the same hash value.
    if committed_value_digest_bytes != *sha256_input_hash
        && &committed_value_digest_bytes != blake3_input_hash.as_bytes()
    {
        return Err(MachineVerificationError::InvalidPublicValues(
            "public input hash mismatch",
        ));
    }

    if !is_recursion_public_values_valid(&InnerSC::default(), public_values) {
        return Err(MachineVerificationError::InvalidPublicValues(
            "recursion public values are invalid",
        ));
    }

    if public_values.vk_root != recursion_vk_root() {
        return Err(MachineVerificationError::InvalidPublicValues(
            "vk_root mismatch",
        ));
    }

    // // `is_complete` should be 1. In the reduce program, this ensures that the proof is fully
    // // reduced.
    if !public_values.is_complete.is_one() {
        return Err(MachineVerificationError::InvalidPublicValues(
            "is_complete is not 1",
        ));
    }

    let vkey_hash: [BabyBear; 8] = vkey_hash
        .chunks_exact(4)
        .map(|bytes| BabyBear::from_canonical_u32(u32::from_le_bytes(bytes.try_into().unwrap())))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    // Verify that the proof is for the sp1 vkey we are expecting.
    if public_values.sp1_vk_digest != vkey_hash {
        return Err(MachineVerificationError::InvalidPublicValues(
            "sp1 vk hash mismatch",
        ));
    }

    Ok(())
}

/// Check if the digest of the public values is correct.
fn is_recursion_public_values_valid(
    config: &InnerSC,
    public_values: &RecursionPublicValues<BabyBear>,
) -> bool {
    let expected_digest = recursion_public_values_digest(config, public_values);
    for (value, expected) in public_values.digest.iter().copied().zip_eq(expected_digest) {
        if value != expected {
            return false;
        }
    }
    true
}

/// Compute the digest of the public values.
fn recursion_public_values_digest(
    config: &InnerSC,
    public_values: &RecursionPublicValues<BabyBear>,
) -> [BabyBear; 8] {
    let hash = InnerHash::new(config.perm.clone());
    let pv_array = public_values.as_array();
    hash.hash_slice(&pv_array[0..NUM_PV_ELMS_TO_HASH])
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Instant;

    const PROOF_BYTES: &[u8] = include_bytes!("../resources/proof.bin");

    #[test]
    fn verify_valid_proof() {
        let now = Instant::now();
        let proof: ShardProof<InnerSC> =
            bincode::serde::decode_from_slice(PROOF_BYTES, bincode::config::legacy())
                .unwrap()
                .0;
        let vk_hash: [u8; 32] =
            hex::decode("6fa8786b1f036c75b3d58774de54421d0172d70234009b3bbc908f4199c1d10b")
                .unwrap()
                .try_into()
                .unwrap();
        let inputs =
            hex::decode("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
                .unwrap();
        verify(vk_hash, &proof, &inputs).unwrap();
        let elapsed_time = now.elapsed();
        std::println!("Running verifier took {} ms.", elapsed_time.as_millis());
    }
}

#[cfg(test)]
mod deserialization {

    use crate::SHRINK_VK_BYTES;
    use sp1_sdk::{Prover, ProverClient, SP1Stdin};
    use sp1_stark::SP1ProverOpts;

    #[test]
    fn shrink_vk_is_correct() {
        const SP1_ELF: &[u8] = include_bytes!("../resources/sp1-program");
        let mut stdin = SP1Stdin::new();
        stdin.write(&b"hello world".to_vec());

        let prover = ProverClient::builder().cpu().build();
        let (pk, _vk) = prover.setup(SP1_ELF);

        let proof = prover.prove(&pk, &stdin).compressed().run().unwrap();

        let shrinked_proof = prover
            .inner()
            .shrink(
                *proof.proof.try_as_compressed().unwrap(),
                SP1ProverOpts::default(),
            )
            .unwrap();

        let shrink_vk_bytes =
            bincode::serde::encode_to_vec(&shrinked_proof.vk, bincode::config::legacy()).unwrap();

        prover.inner().recursion_vk_root;

        assert_eq!(SHRINK_VK_BYTES, &shrink_vk_bytes[..]);
    }
}
