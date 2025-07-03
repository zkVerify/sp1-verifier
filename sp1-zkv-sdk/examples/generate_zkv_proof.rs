use sp1_elf::SP1_ELF;
use sp1_sdk::{Prover, ProverClient, SP1Stdin};
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
    let vkey_hash = vk.convert_to_zkv();

    sp1_zkv_sdk::verify(&zkv_proof, &vkey_hash).unwrap();
}
