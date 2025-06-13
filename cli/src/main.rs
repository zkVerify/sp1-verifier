use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod proof;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a compressed proof
    GenerateProof {
        /// The output file of the proof
        #[arg(long)]
        proof: PathBuf,
        /// The output file of the vk
        #[arg(long)]
        vk: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateProof { proof, vk } => proof::generate_and_write_to_file(proof, vk),
    }
}
