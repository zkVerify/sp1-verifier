use std::{fs::File, path::Path};

use sp1_sdk::{
    Prover, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey,
    include_elf,
};
use sp1_stark::SP1ProverOpts;

const SP1_ELF: &[u8] = include_elf!("sp1-program");

pub fn generate() -> (SP1ProofWithPublicValues, SP1VerifyingKey) {
    let mut stdin = SP1Stdin::new();
    stdin.write(&b"hello world".to_vec());

    let prover = ProverClient::builder().cpu().build();
    let (pk, vk) = prover.setup(SP1_ELF);

    let vk_serialized = bincode::serde::encode_to_vec(&vk, bincode::config::standard()).unwrap();
    println!("vk size: {} bytes", vk_serialized.len());

    let proof = prover.prove(&pk, &stdin).compressed().run().unwrap();
    prover.verify(&proof, &vk).unwrap();
    println!("public values: {}", proof.public_values.raw());

    let shrinked_proof = prover
        .inner()
        .shrink(
            *proof.proof.try_as_compressed().unwrap(),
            SP1ProverOpts::default(),
        )
        .unwrap();
    let sp1_proof = SP1ProofWithPublicValues {
        proof: SP1Proof::Compressed(Box::new(shrinked_proof)),
        public_values: proof.public_values,
        sp1_version: proof.sp1_version,
        tee_proof: proof.tee_proof,
    };
    (sp1_proof, vk)
}

pub fn generate_and_write_to_file<P: AsRef<Path>>(path_proof: P, path_vk: P) {
    let (proof, vk) = generate();
    proof.save(path_proof).unwrap();

    bincode::serde::encode_into_std_write(
        &vk,
        &mut File::create(path_vk).unwrap(),
        bincode::config::legacy(),
    )
    .unwrap();
}
