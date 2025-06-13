use sdk::ZkvAdapterT;
use sdk::ZkvProver;
use sp1_sdk::{ProverClient, SP1Stdin, include_elf};

const ELF: &[u8] = include_elf!("sp1-program");

#[test]
fn prove_and_verify() {
    // Setup the prover client.
    let client = ProverClient::builder().cpu().build().zkv_adapter();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&b"hello world".to_vec());

    // Setup the program for proving.
    let (pk, vk) = client.setup(ELF);

    // Generate the proof
    let proof = client.prove(&pk, &stdin).expect("failed to generate proof");
    println!("Successfully generated proof!");

    // Verify the proof.
    client.verify(&proof, &vk).expect("failed to verify proof");
    println!("Successfully verified proof!");
}
