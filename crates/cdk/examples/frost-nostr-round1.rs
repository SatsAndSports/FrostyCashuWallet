#![allow(missing_docs)]

use std::env;

use bitcoin::hashes::{sha256, Hash};
use cdk::nuts::SecretKey as CashuSecretKey;
use nostr_sdk::{Keys, ToBech32};

#[path = "support/frost_nostr.rs"]
mod frost_nostr;

use frost_nostr::{
    build_roster, build_signing_package, connect_coordinator, dealer_signer_packages,
    run_coordinator_round1, spawn_signers, wait_for_all_signers_ready, DemoResult,
    NostrFrostCoordinatorConfig, Round1Request, SigningPhase, DEFAULT_MAX_SIGNERS,
    DEFAULT_NOSTR_RELAY_URL, DEFAULT_NOSTR_TIMEOUT_SECS, DEFAULT_THRESHOLD, DEMO_SECRET_HEX,
};

fn env_u64(name: &str, default: u64) -> DemoResult<u64> {
    match env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(_) => Ok(default),
    }
}

#[tokio::main]
async fn main() -> DemoResult<()> {
    let relay_url =
        env::var("NOSTR_RELAY_URL").unwrap_or_else(|_| DEFAULT_NOSTR_RELAY_URL.to_string());
    let timeout_secs = env_u64("NOSTR_ROUND1_TIMEOUT_SECS", DEFAULT_NOSTR_TIMEOUT_SECS)?;
    let coordinator_keys = match env::var("NOSTR_COORDINATOR_NSEC") {
        Ok(nsec) => Keys::parse(&nsec)?,
        Err(_) => Keys::generate(),
    };
    let source_secret = CashuSecretKey::from_hex(DEMO_SECRET_HEX)?;
    let signer_packages = dealer_signer_packages(
        &source_secret,
        &relay_url,
        DEFAULT_MAX_SIGNERS,
        DEFAULT_THRESHOLD,
    )?;
    let session_id = format!("frost-round1-{}", uuid::Uuid::new_v4());
    let sig_all_message = format!("cashu-sigall-demo:{}:round1-over-nostr", session_id);
    let digest = sha256::Hash::hash(sig_all_message.as_bytes());
    let participant_ids = signer_packages
        .iter()
        .map(|p| p.participant_id)
        .collect::<Vec<_>>();
    let round1_request = Round1Request {
        session_id: session_id.clone(),
        phase: "round1_request".to_string(),
        signable_message: sig_all_message,
        digest_hex: digest.to_string(),
        threshold: DEFAULT_THRESHOLD,
        participant_ids,
    };

    println!("FROST Nostr round-1 demo");
    println!("Relay: {}", relay_url);
    println!("Session: {}", session_id);
    println!(
        "Coordinator npub: {}",
        coordinator_keys.public_key().to_bech32()?
    );
    println!(
        "Threshold: {}-of-{}",
        DEFAULT_THRESHOLD, DEFAULT_MAX_SIGNERS
    );

    let roster = build_roster(&signer_packages)?;
    let config = NostrFrostCoordinatorConfig {
        relay_url,
        coordinator_keys: coordinator_keys.clone(),
        timeout_secs,
        max_signers: DEFAULT_MAX_SIGNERS,
        threshold: DEFAULT_THRESHOLD,
        session_id: Some(session_id.clone()),
        session_prefix: "frost-round1".to_string(),
    };

    let (mut ready_rx, signer_handles) = spawn_signers(
        signer_packages,
        coordinator_keys.public_key(),
        round1_request.clone(),
        SigningPhase::Round1,
    )
    .await?;
    wait_for_all_signers_ready(&mut ready_rx, DEFAULT_MAX_SIGNERS).await?;

    let coordinator_client = connect_coordinator(&config, &session_id).await?;
    let accepted = run_coordinator_round1(
        &coordinator_client,
        &session_id,
        &round1_request,
        &roster,
        DEFAULT_THRESHOLD as usize,
        timeout_secs,
    )
    .await?;

    println!("\nAccepted round-1 commitments:");
    for a in &accepted {
        println!(
            "- participant {} via {}",
            a.participant_id,
            a.author.to_bech32()?
        );
    }

    let (selected_ids, signing_package) = build_signing_package(accepted, digest.as_byte_array())?;
    println!("\nCoordinator selected signers: {:?}", selected_ids);
    println!(
        "Constructed local signing package with {} commitments",
        signing_package.signing_commitments().len()
    );

    coordinator_client.disconnect().await;
    for handle in signer_handles {
        handle.await??;
    }

    println!("\nNostr round-1 demo succeeded");
    Ok(())
}
