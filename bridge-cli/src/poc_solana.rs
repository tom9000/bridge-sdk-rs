use anyhow::Result;
use clap::{Args, Subcommand};
#[cfg(feature = "gated-poc-solana-optimistic")]
use solana_optimistic_poc_client::{
    decode_message_base64, Claim, PocConfig, PocSigner, SolanaOptimisticPocClient, SolanaProof,
};

#[derive(Subcommand, Debug)]
pub enum PocSolanaCommand {
    /// Submit an optimistic claim
    #[cfg(feature = "gated-poc-solana-optimistic")]
    Init(InitArgs),
    /// Challenge an optimistic claim
    #[cfg(feature = "gated-poc-solana-optimistic")]
    Challenge(ChallengeArgs),
    /// Finalize after challenge period
    #[cfg(feature = "gated-poc-solana-optimistic")]
    Finalize(FinalizeArgs),
}

#[derive(Args, Debug)]
pub struct InitArgs {
    #[arg(long)]
    pub verifier_account: String,
    #[arg(long)]
    pub near_rpc: String,
    #[arg(long)]
    pub solana_rpc: String,
    #[arg(long)]
    pub bond_yocto: u128,
    #[arg(long)]
    pub challenge_period_secs: u64,
    #[arg(long)]
    pub signer_account: String,
    #[arg(long)]
    pub signer_secret_key: String,
    #[arg(long)]
    pub amount: u64,
    #[arg(long)]
    pub recipient: String,
    #[arg(long)]
    pub nonce: u64,
    #[arg(long)]
    pub tx_sig: String,
    #[arg(long)]
    pub slot: u64,
    #[arg(long)]
    pub log_index: u64,
    #[arg(long)]
    pub message_base64: String,
}

#[derive(Args, Debug)]
pub struct ChallengeArgs {
    #[arg(long)]
    pub verifier_account: String,
    #[arg(long)]
    pub near_rpc: String,
    #[arg(long)]
    pub solana_rpc: String,
    #[arg(long)]
    pub signer_account: String,
    #[arg(long)]
    pub signer_secret_key: String,
    #[arg(long)]
    pub transfer_id: String,
    #[arg(long)]
    pub correct_message_base64: String,
}

#[derive(Args, Debug)]
pub struct FinalizeArgs {
    #[arg(long)]
    pub verifier_account: String,
    #[arg(long)]
    pub near_rpc: String,
    #[arg(long)]
    pub solana_rpc: String,
    #[arg(long)]
    pub signer_account: String,
    #[arg(long)]
    pub signer_secret_key: String,
    #[arg(long)]
    pub transfer_id: String,
}

#[cfg(feature = "gated-poc-solana-optimistic")]
pub async fn handle_poc_solana(cmd: PocSolanaCommand) -> Result<()> {
    match cmd {
        PocSolanaCommand::Init(args) => {
            let config = PocConfig {
                verifier_account: args.verifier_account.parse()?,
                near_rpc: args.near_rpc,
                solana_rpc: args.solana_rpc,
                bond_yocto: args.bond_yocto,
                challenge_period_secs: args.challenge_period_secs,
            };
            let signer = PocSigner {
                account_id: args.signer_account.parse()?,
                secret_key: args.signer_secret_key.parse()?,
            };
            // Validate message payload
            decode_message_base64(&args.message_base64)?;

            let claim = Claim {
                amount: args.amount,
                recipient: args.recipient.parse()?,
                nonce: args.nonce,
                proof: SolanaProof {
                    tx_sig: args.tx_sig,
                    slot: args.slot,
                    log_index: args.log_index,
                    message_base64: args.message_base64,
                },
            };
            let client = SolanaOptimisticPocClient::new(config);
            let transfer_id = client.init_claim(&signer, &claim).await?;
            println!("Submitted optimistic init. transfer_id={}", transfer_id);
        }
        PocSolanaCommand::Challenge(args) => {
            let config = PocConfig {
                verifier_account: args.verifier_account.parse()?,
                near_rpc: args.near_rpc,
                solana_rpc: args.solana_rpc,
                bond_yocto: 0,
                challenge_period_secs: 0,
            };
            let signer = PocSigner {
                account_id: args.signer_account.parse()?,
                secret_key: args.signer_secret_key.parse()?,
            };
            decode_message_base64(&args.correct_message_base64)?;
            let client = SolanaOptimisticPocClient::new(config);
            client
                .challenge(&signer, &args.transfer_id, &args.correct_message_base64)
                .await?;
            println!("Challenge submitted for transfer_id={}", args.transfer_id);
        }
        PocSolanaCommand::Finalize(args) => {
            let config = PocConfig {
                verifier_account: args.verifier_account.parse()?,
                near_rpc: args.near_rpc,
                solana_rpc: args.solana_rpc,
                bond_yocto: 0,
                challenge_period_secs: 0,
            };
            let signer = PocSigner {
                account_id: args.signer_account.parse()?,
                secret_key: args.signer_secret_key.parse()?,
            };
            let client = SolanaOptimisticPocClient::new(config);
            client.finalize(&signer, &args.transfer_id).await?;
            println!("Finalize submitted for transfer_id={}", args.transfer_id);
        }
    }
    Ok(())
}
