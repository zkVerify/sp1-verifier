use clap::{Parser, Subcommand};
use p3_field::PrimeField32;
use sp1_sdk::{HashableKey, Prover, ProverClient, SP1Stdin, include_elf};
use sp1_stark::SP1ProverOpts;
use std::{
    fs::{self, File},
    path::PathBuf,
};

const SP1_ELF: &[u8] = include_elf!("sp1-program");

/// A simple CLI to generate and verify SP1 proofs.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate an example SP1 proof, verification key, and public inputs.
    GenerateProof {
        /// The path for the proof output file.
        #[arg(long, default_value = "proof.bin")]
        proof: PathBuf,

        /// The path for the verification key output file.
        #[arg(long, default_value = "vk.json")]
        vk: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::GenerateProof { proof, vk } => {
            if let Err(e) = generate_proof(proof, vk) {
                eprintln!("Error generating proof: {e}");
                std::process::exit(1);
            }
        }
    }
}

/// Generates the proof, verification key, and public inputs.
fn generate_proof(proof_path: &PathBuf, vk_path: &PathBuf) -> Result<(), std::io::Error> {
    println!("Generating example proof, verification key, and public inputs...");

    // Create parent directories if they don't exist.
    for path in [proof_path, vk_path] {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
    }

    let mut stdin = SP1Stdin::new();
    stdin.write(&b"hello world".to_vec());

    let prover = ProverClient::builder().cpu().build();
    let (pk, vk) = prover.setup(SP1_ELF);

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

    bincode::serde::encode_into_std_write(
        &shrinked_proof.proof,
        &mut File::create(proof_path).unwrap(),
        bincode::config::legacy(),
    )
    .unwrap();

    let vkey_hash: Vec<u8> = vk
        .hash_babybear()
        .iter()
        .flat_map(|el| el.as_canonical_u32().to_le_bytes())
        .collect();

    println!("Public inputs: {:?}", proof.public_values.raw());
    println!("Vk hash: {}", hex::encode(vkey_hash));

    println!("\nGeneration complete!");
    Ok(())
}
