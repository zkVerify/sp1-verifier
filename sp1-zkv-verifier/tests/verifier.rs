use rstest::{fixture, rstest};
use sp1_zkv_verifier::ShardProof;
use std::fs::File;

#[fixture]
fn valid_proof() -> ShardProof {
    bincode::serde::decode_from_std_read(
        &mut File::open("resources/proof.bin").unwrap(),
        bincode::config::legacy(),
    )
    .unwrap()
}

#[fixture]
fn valid_vk_hash() -> [u8; 32] {
    hex::decode("6fa8786b1f036c75b3d58774de54421d0172d70234009b3bbc908f4199c1d10b")
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
fn invalid_proof(mut valid_proof: ShardProof) -> ShardProof {
    valid_proof.opening_proof.fri_proof.query_proofs[0].commit_phase_openings[0].sibling_value =
        Default::default();
    valid_proof
}

mod verifier_should_accept_if {
    use super::*;

    #[rstest]
    fn proof_vk_and_inputs_are_valid(
        valid_proof: ShardProof,
        valid_vk_hash: [u8; 32],
        valid_inputs: Vec<u8>,
    ) {
        assert!(sp1_zkv_verifier::verify(&valid_vk_hash, &valid_proof, &valid_inputs).is_ok());
    }
}

mod verifier_should_reject_if {
    use super::*;

    #[rstest]
    fn vk_hash_is_invalid(
        valid_proof: ShardProof,
        invalid_vk_hash: [u8; 32],
        valid_inputs: Vec<u8>,
    ) {
        assert!(sp1_zkv_verifier::verify(&invalid_vk_hash, &valid_proof, &valid_inputs).is_err());
    }

    #[rstest]
    fn proof_is_invalid(invalid_proof: ShardProof, valid_vk_hash: [u8; 32], valid_inputs: Vec<u8>) {
        assert!(sp1_zkv_verifier::verify(&valid_vk_hash, &invalid_proof, &valid_inputs).is_err());
    }

    #[rstest]
    fn inputs_are_invalid(
        valid_proof: ShardProof,
        valid_vk_hash: [u8; 32],
        invalid_inputs: Vec<u8>,
    ) {
        assert!(sp1_zkv_verifier::verify(&valid_vk_hash, &valid_proof, &invalid_inputs).is_err());
    }
}
