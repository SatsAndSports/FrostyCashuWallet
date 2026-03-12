#![allow(missing_docs)]

use std::env;
use std::sync::Arc;
use std::time::Duration;

#[path = "support/frost_nostr.rs"]
mod frost_nostr_support;
#[path = "support/p2pk_sigall_swap.rs"]
mod p2pk_sigall_swap_support;

use cdk::mint_url::MintUrl;
use cdk::nuts::nut00::ProofsMethods;
use cdk::nuts::{
    CurrencyUnit, PaymentMethod, SecretKey as CashuSecretKey, SpendingConditionVerification,
};
use cdk::wallet::{HttpClient, MintConnector, WalletBuilder};
use cdk::Amount;
use cdk_sqlite::wallet::memory;
use frost_nostr_support::{
    sign_message_via_nostr, NostrFrostCoordinatorConfig, DEFAULT_NOSTR_RELAY_URL,
    DEFAULT_NOSTR_TIMEOUT_SECS,
};
use nostr_sdk::{Keys, SecretKey as NostrSecretKey, ToBech32};
use p2pk_sigall_swap_support::{
    prepare_p2pk_sigall_swap, FrostDemoGroup, DEFAULT_FROST_MAX_SIGNERS, DEFAULT_FROST_THRESHOLD,
    DEFAULT_LOCK_AMOUNT_SATS, DEMO_SECRET_HEX,
};
use rand::random;

fn env_u64(name: &str, default: u64) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    match env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(_) => Ok(default),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mint_url: MintUrl = env::var("CDK_MINT_URL")
        .unwrap_or_else(|_| "https://fake.thesimplekid.dev".to_string())
        .parse()?;
    let lock_amount_sats = env_u64("CDK_LOCK_AMOUNT", DEFAULT_LOCK_AMOUNT_SATS)?;
    let fund_amount_sats = env_u64("CDK_FUND_AMOUNT", lock_amount_sats.saturating_add(32))?;
    let frost_max_signers =
        env_u64("CDK_FROST_MAX_SIGNERS", DEFAULT_FROST_MAX_SIGNERS as u64)? as u16;
    let frost_threshold = env_u64("CDK_FROST_THRESHOLD", DEFAULT_FROST_THRESHOLD as u64)? as u16;

    let default_nsec = NostrSecretKey::from_hex(DEMO_SECRET_HEX)?.to_bech32()?;
    let seed_nsec = env::var("NOSTR_NSEC").unwrap_or(default_nsec);
    let nostr_keys = Keys::parse(&seed_nsec)?;
    let signer = CashuSecretKey::from_slice(&nostr_keys.secret_key().to_secret_bytes())?;
    let frost_group = if frost_max_signers == DEFAULT_FROST_MAX_SIGNERS
        && frost_threshold == DEFAULT_FROST_THRESHOLD
    {
        FrostDemoGroup::from_existing_secret(&signer)?
    } else {
        FrostDemoGroup::from_existing_secret_with_params(
            &signer,
            frost_max_signers,
            frost_threshold,
        )?
    };

    let localstore = Arc::new(memory::empty().await?);
    let connector: Arc<dyn MintConnector + Send + Sync> =
        Arc::new(HttpClient::new(mint_url.clone(), None));
    let wallet = WalletBuilder::new()
        .mint_url(mint_url.clone())
        .unit(CurrencyUnit::Sat)
        .localstore(localstore)
        .seed(random::<[u8; 64]>())
        .shared_client(connector.clone())
        .build()?;

    let quote = wallet
        .mint_quote(
            PaymentMethod::BOLT11,
            Some(Amount::from(fund_amount_sats)),
            None,
            None,
        )
        .await?;
    let minted_proofs = wallet
        .wait_and_mint_quote(
            quote,
            Default::default(),
            Default::default(),
            Duration::from_secs(10),
        )
        .await?;

    println!("Mint URL: {}", mint_url);
    println!("Funded wallet with {} sats", minted_proofs.total_amount()?);
    println!("FROST transport: Nostr");
    println!("Seed signer pubkey: {}", signer.public_key());
    println!("FROST group pubkey: {}", frost_group.group_public_key);
    println!(
        "FROST quorum: {}-of-{}",
        frost_group.threshold, frost_group.max_signers
    );
    println!("Selected signers: {}", frost_group.selected_signer_count());
    println!("Seed nsec: {}", seed_nsec);

    let prepared = prepare_p2pk_sigall_swap(
        &wallet,
        Amount::from(lock_amount_sats),
        frost_group.group_public_key,
    )
    .await?;

    println!("\nLocked token amount: {}", prepared.lock_amount);
    println!("Locked token value: {}", prepared.locked_token.value()?);
    println!("Locking swap fee: {}", prepared.lock_swap_fee);
    println!("Locked proof count: {}", prepared.locked_proofs.len());
    println!("Locked proofs total: {}", prepared.input_amount);
    println!("Spend-side input fee: {}", prepared.input_fee);
    println!("Unlocked output amount: {}", prepared.output_amount);
    println!("Locked token:\n{}", prepared.locked_token_string);

    match prepared.unsigned_swap_request.verify_spending_conditions() {
        Ok(()) => println!("Unsigned request unexpectedly verified"),
        Err(err) => println!("Unsigned request fails as expected: {}", err),
    }

    let payload = prepared.signing_payload();
    let relay_url =
        env::var("NOSTR_RELAY_URL").unwrap_or_else(|_| DEFAULT_NOSTR_RELAY_URL.to_string());
    let timeout_secs = env_u64("NOSTR_FROST_TIMEOUT_SECS", DEFAULT_NOSTR_TIMEOUT_SECS)?;
    let coordinator_keys = match env::var("NOSTR_COORDINATOR_NSEC") {
        Ok(nsec) => Keys::parse(&nsec)?,
        Err(_) => Keys::generate(),
    };
    let config = NostrFrostCoordinatorConfig {
        relay_url,
        coordinator_keys: coordinator_keys.clone(),
        timeout_secs,
        max_signers: frost_group.max_signers,
        threshold: frost_group.threshold,
        session_id: env::var("CDK_FROST_SESSION_ID").ok(),
        session_prefix: "cashu-swap".to_string(),
    };
    let result = sign_message_via_nostr(&signer, &payload.message, &config).await?;
    let signed = prepared.build_signed_swap(&payload, result.signature_hex)?;

    println!(
        "Nostr coordinator npub: {}",
        coordinator_keys.public_key().to_bech32()?
    );
    println!("Nostr relay: {}", config.relay_url);
    println!("Nostr session: {}", result.session_id);
    println!(
        "Nostr selected signers: {:?}",
        result.selected_participant_ids
    );

    println!("\nSIG_ALL message:\n{}", signed.message);
    println!("SHA256 prehash: {}", signed.digest_hex);
    println!("FROST signature: {}", signed.signature_hex);

    let completed = prepared.execute_signed_swap(connector, signed).await?;

    println!(
        "\nSubmitted signature: {}",
        completed.signed_swap.signature_hex
    );
    println!(
        "Unlocked proofs total: {}",
        completed.unlocked_proofs.total_amount()?
    );
    println!(
        "\nUnlocked token amount: {}",
        completed.unlocked_token.value()?
    );
    println!("Unlocked token:\n{}", completed.unlocked_token);

    Ok(())
}
