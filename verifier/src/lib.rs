#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use executor::{Block, Executor, Program, RecursionPublicValues};
use lazy_static::lazy_static;
use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
use p3_field::{PrimeField32, extension::BinomialExtensionField};
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};
use sha2::{Digest, Sha256};

const WRAP_PROGRAM_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/wrap_program.bin"));
lazy_static! {
    static ref VERIFIER_PROGRAM: Program<BabyBear> =
        bincode::serde::decode_from_slice(WRAP_PROGRAM_BYTES, bincode::config::legacy())
            .unwrap()
            .0;
}

pub fn verify(witness_stream: Vec<Block<BabyBear>>, pubs: Vec<u8>, vk_hash: [BabyBear; 8]) {
    let perm = executor::perm();
    let mut executor = Executor::<_, BinomialExtensionField<BabyBear, 4>, _>::new(perm.clone());
    executor.witness_stream = witness_stream.into();
    executor.execute(&VERIFIER_PROGRAM);
    let public_input = executor.public_values.unwrap();
    let committed_value_digets: Vec<_> = public_input
        .committed_value_digest
        .iter()
        .flat_map(|w| w.0.iter().map(|x| x.as_canonical_u32() as u8))
        .collect();
    assert_eq!(committed_value_digets, sha256_hash(&pubs));
    assert_root_public_values_valid(perm.clone(), &public_input);
    assert_eq!(public_input.sp1_vk_digest, vk_hash);
}

fn assert_root_public_values_valid(
    perm: Poseidon2<BabyBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>,
    public_values: &RecursionPublicValues<BabyBear>,
) {
    let expected_digest = root_public_values_digest(perm, public_values);
    for (value, expected) in public_values.digest.iter().zip(&expected_digest) {
        assert_eq!(value, expected);
    }
}

fn root_public_values_digest(
    perm: Poseidon2<BabyBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>,
    public_values: &RecursionPublicValues<BabyBear>,
) -> [BabyBear; 8] {
    let hash = PaddingFreeSponge::<_, 16, 8, 8>::new(perm);
    let input = (public_values.sp1_vk_digest)
        .into_iter()
        .chain(
            (public_values.committed_value_digest)
                .into_iter()
                .flat_map(|word| word.0.into_iter()),
        )
        .collect::<Vec<_>>();
    hash.hash_slice(&input)
}

pub fn sha256_hash(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::{fs::File, time::Instant, vec::Vec};

    use super::*;

    use executor::Block;
    use sp1_core_executor::SP1ReduceProof;
    use sp1_recursion_circuit::{machine::SP1CompressWitnessValues, witness::Witnessable};
    use sp1_recursion_compiler::config::InnerConfig;
    use sp1_sdk::{HashableKey, Prover, ProverClient, SP1ProofWithPublicValues, SP1VerifyingKey};
    use std::vec;

    #[test]
    fn verify_proof() {
        let sp1_proof = SP1ProofWithPublicValues::load(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/resources/sp1_shrink_proof.bin"
        ))
        .unwrap();
        let mut vk_file =
            File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/resources/sp1_vk.bin")).unwrap();
        let sp1_vk: SP1VerifyingKey =
            bincode::serde::decode_from_std_read(&mut vk_file, bincode::config::standard())
                .unwrap();
        let SP1ReduceProof { vk, proof } = *sp1_proof.clone().proof.try_as_compressed().unwrap();

        let input = SP1CompressWitnessValues {
            vks_and_proofs: vec![(vk.clone(), proof)],
            is_complete: true,
        };
        let input_with_merkle = ProverClient::builder()
            .cpu()
            .build()
            .inner()
            .make_merkle_proofs(input);

        let mut witness_stream = Vec::new();
        Witnessable::<InnerConfig>::write(&input_with_merkle, &mut witness_stream);
        let witness_stream: Vec<Block<_>> = witness_stream.iter().map(|a| a.0.into()).collect();

        let now = Instant::now();
        verify(
            witness_stream,
            sp1_proof.public_values.to_vec(),
            sp1_vk.hash_babybear(),
        );
        let elapsed_time = now.elapsed();
        println!("Running verify() took {} ms.", elapsed_time.as_millis());
    }
}
