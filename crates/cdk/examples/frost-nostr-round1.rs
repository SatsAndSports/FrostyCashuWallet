#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::env;
use std::time::Duration;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::prelude::FromHex;
use cdk::nuts::SecretKey as CashuSecretKey;
use frost_secp256k1_tr as frost;
use nostr_sdk::{Client, EventBuilder, Filter, Keys, Kind, RelayPoolNotification, Tag, ToBech32};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

const ROUND1_REQUEST_KIND: u16 = 23102;
const ROUND1_RESPONSE_KIND: u16 = 23103;
const DEFAULT_RELAY_URL: &str = "ws://127.0.0.1:7777";
const DEFAULT_TIMEOUT_SECS: u64 = 10;
const DEMO_SECRET_HEX: &str = "e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734";
const MAX_SIGNERS: u16 = 3;
const THRESHOLD: u16 = 2;

type DemoResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DealerSignerPackage {
    participant_id: u16,
    nostr_nsec: String,
    relay_url: String,
    key_package: frost::keys::KeyPackage,
    public_key_package: frost::keys::PublicKeyPackage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Round1Request {
    session_id: String,
    phase: String,
    sig_all_message: String,
    digest_hex: String,
    threshold: u16,
    participant_ids: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Round1CommitmentResponse {
    session_id: String,
    phase: String,
    participant_id: u16,
    commitments: frost::round1::SigningCommitments,
}

#[derive(Debug)]
struct AcceptedCommitment {
    participant_id: u16,
    author: nostr_sdk::PublicKey,
    response: Round1CommitmentResponse,
}

#[derive(Debug)]
struct SignerRound1Outcome {
    participant_id: u16,
    response_event_id: nostr_sdk::EventId,
}

fn env_u64(name: &str, default: u64) -> DemoResult<u64> {
    match env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(_) => Ok(default),
    }
}

#[tokio::main]
async fn main() -> DemoResult<()> {
    let relay_url = env::var("NOSTR_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY_URL.to_string());
    let timeout_secs = env_u64("NOSTR_ROUND1_TIMEOUT_SECS", DEFAULT_TIMEOUT_SECS)?;
    let coordinator_keys = match env::var("NOSTR_COORDINATOR_NSEC") {
        Ok(nsec) => Keys::parse(&nsec)?,
        Err(_) => Keys::generate(),
    };
    let signer_packages = dealer_signer_packages(&relay_url)?;
    let session_id = format!("frost-round1-{}", uuid::Uuid::new_v4());
    let sig_all_message = format!("cashu-sigall-demo:{}:{}", session_id, "round1-over-nostr");
    let digest_hex = sha256::Hash::hash(sig_all_message.as_bytes()).to_string();
    let participant_ids = signer_packages
        .iter()
        .map(|package| package.participant_id)
        .collect::<Vec<_>>();
    let round1_request = Round1Request {
        session_id: session_id.clone(),
        phase: "round1_request".to_string(),
        sig_all_message,
        digest_hex,
        threshold: THRESHOLD,
        participant_ids: participant_ids.clone(),
    };

    println!("FROST Nostr round-1 demo");
    println!("Relay: {}", relay_url);
    println!("Session: {}", session_id);
    println!(
        "Coordinator npub: {}",
        coordinator_keys.public_key().to_bech32()?
    );
    println!("Threshold: {}-of-{}", THRESHOLD, MAX_SIGNERS);
    println!(
        "Round-1 request:\n{}",
        serde_json::to_string_pretty(&round1_request)?
    );

    for package in &signer_packages {
        println!(
            "\nDealer package for participant {}:\n{}",
            package.participant_id,
            serde_json::to_string_pretty(package)?
        );
    }

    let roster = signer_packages
        .iter()
        .map(|package| {
            let keys = Keys::parse(&package.nostr_nsec)?;
            Ok((package.participant_id, keys.public_key()))
        })
        .collect::<DemoResult<BTreeMap<_, _>>>()?;

    let (ready_tx, mut ready_rx) = mpsc::channel::<u16>(MAX_SIGNERS as usize);
    let mut signer_handles = Vec::new();

    for signer_package in signer_packages.clone() {
        let ready_tx = ready_tx.clone();
        let coordinator_pubkey = coordinator_keys.public_key();
        let request = round1_request.clone();
        signer_handles.push(tokio::spawn(async move {
            run_signer_round1(signer_package, coordinator_pubkey, request, ready_tx).await
        }));
    }
    drop(ready_tx);

    for _ in 0..MAX_SIGNERS {
        let participant_id = ready_rx
            .recv()
            .await
            .ok_or("failed to wait for signer readiness")?;
        println!("Signer {} is subscribed and ready", participant_id);
    }

    let coordinator_client = Client::new(coordinator_keys.clone());
    coordinator_client.add_relay(relay_url.as_str()).await?;
    coordinator_client.connect().await;

    let response_filter = Filter::new()
        .kind(Kind::Custom(ROUND1_RESPONSE_KIND))
        .identifier(session_id.clone());
    coordinator_client.subscribe(response_filter, None).await?;

    sleep(Duration::from_millis(250)).await;

    let output = coordinator_client
        .send_event_builder(
            EventBuilder::new(
                Kind::Custom(ROUND1_REQUEST_KIND),
                serde_json::to_string(&round1_request)?,
            )
            .tag(Tag::identifier(session_id.clone())),
        )
        .await?;
    println!(
        "Published round-1 request event: {}",
        output.id().to_bech32()?
    );

    let accepted = wait_for_round1_commitments(
        &coordinator_client,
        &session_id,
        &roster,
        THRESHOLD as usize,
        timeout_secs,
    )
    .await?;

    println!("\nAccepted round-1 commitments:");
    for accepted_commitment in &accepted {
        println!(
            "- participant {} via {}",
            accepted_commitment.participant_id,
            accepted_commitment.author.to_bech32()?
        );
    }

    let selected_signer_ids = accepted
        .iter()
        .map(|accepted_commitment| accepted_commitment.participant_id)
        .collect::<Vec<_>>();
    let commitments_map = accepted
        .into_iter()
        .map(|accepted_commitment| {
            let identifier = frost::Identifier::try_from(accepted_commitment.participant_id)?;
            Ok((identifier, accepted_commitment.response.commitments))
        })
        .collect::<DemoResult<BTreeMap<_, _>>>()?;
    let digest_bytes = <[u8; 32]>::from_hex(&round1_request.digest_hex)?;
    let signing_package = frost::SigningPackage::new(commitments_map, &digest_bytes);

    println!("\nCoordinator selected signers: {:?}", selected_signer_ids);
    println!(
        "Constructed local signing package with {} commitments over message bytes: {}",
        signing_package.signing_commitments().len(),
        round1_request.digest_hex
    );

    coordinator_client.disconnect().await;

    for handle in signer_handles {
        let outcome = handle.await??;
        println!(
            "Signer {} published round-1 commitment event: {}",
            outcome.participant_id,
            outcome.response_event_id.to_bech32()?
        );
    }

    println!("\nNostr round-1 demo succeeded");

    Ok(())
}

fn dealer_signer_packages(relay_url: &str) -> DemoResult<Vec<DealerSignerPackage>> {
    let source_secret = CashuSecretKey::from_hex(DEMO_SECRET_HEX)?;
    let frost_signing_key = frost::SigningKey::deserialize(source_secret.as_secret_bytes())?;
    let mut rng = frost::rand_core::OsRng;
    let (secret_shares, public_key_package) = frost::keys::split(
        &frost_signing_key,
        MAX_SIGNERS,
        THRESHOLD,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )?;

    let mut packages = Vec::new();
    for (index, (_identifier, secret_share)) in secret_shares.into_iter().enumerate() {
        let participant_id = (index as u16) + 1;
        let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
        let expected_identifier = frost::Identifier::try_from(participant_id)?;
        if key_package.identifier() != &expected_identifier {
            return Err("dealer produced unexpected participant identifier ordering".into());
        }

        let nostr_keys = Keys::generate();
        packages.push(DealerSignerPackage {
            participant_id,
            nostr_nsec: nostr_keys.secret_key().to_bech32()?,
            relay_url: relay_url.to_string(),
            key_package,
            public_key_package: public_key_package.clone(),
        });
    }

    Ok(packages)
}

async fn run_signer_round1(
    signer_package: DealerSignerPackage,
    coordinator_pubkey: nostr_sdk::PublicKey,
    request: Round1Request,
    ready_tx: mpsc::Sender<u16>,
) -> DemoResult<SignerRound1Outcome> {
    let signer_keys = Keys::parse(&signer_package.nostr_nsec)?;
    let signer_client = Client::new(signer_keys);
    signer_client
        .add_relay(signer_package.relay_url.as_str())
        .await?;
    signer_client.connect().await;

    let request_filter = Filter::new()
        .kind(Kind::Custom(ROUND1_REQUEST_KIND))
        .author(coordinator_pubkey)
        .identifier(request.session_id.clone());
    signer_client.subscribe(request_filter, None).await?;

    ready_tx.send(signer_package.participant_id).await?;

    let incoming_request = wait_for_round1_request(&signer_client, &request.session_id).await?;
    if incoming_request.digest_hex != request.digest_hex {
        return Err("coordinator published an unexpected digest".into());
    }
    if !incoming_request
        .participant_ids
        .contains(&signer_package.participant_id)
    {
        return Err("signer was not included in the round-1 request".into());
    }

    let key_package = signer_package.key_package;
    let mut rng = frost::rand_core::OsRng;
    let (_nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut rng);

    let response = Round1CommitmentResponse {
        session_id: incoming_request.session_id,
        phase: "round1_commitment".to_string(),
        participant_id: signer_package.participant_id,
        commitments,
    };
    let output = signer_client
        .send_event_builder(
            EventBuilder::new(
                Kind::Custom(ROUND1_RESPONSE_KIND),
                serde_json::to_string(&response)?,
            )
            .tag(Tag::identifier(request.session_id)),
        )
        .await?;

    signer_client.disconnect().await;

    Ok(SignerRound1Outcome {
        participant_id: signer_package.participant_id,
        response_event_id: output.id().clone(),
    })
}

async fn wait_for_round1_request(client: &Client, session_id: &str) -> DemoResult<Round1Request> {
    let mut notifications = client.notifications();

    loop {
        let notification = notifications.recv().await?;
        if let RelayPoolNotification::Event { event, .. } = notification {
            if event.kind != Kind::Custom(ROUND1_REQUEST_KIND) {
                continue;
            }

            let request: Round1Request = serde_json::from_str(&event.content)?;
            if request.session_id == session_id {
                return Ok(request);
            }
        }
    }
}

async fn wait_for_round1_commitments(
    client: &Client,
    session_id: &str,
    roster: &BTreeMap<u16, nostr_sdk::PublicKey>,
    threshold: usize,
    timeout_secs: u64,
) -> DemoResult<Vec<AcceptedCommitment>> {
    let mut notifications = client.notifications();

    timeout(Duration::from_secs(timeout_secs), async move {
        let mut accepted = BTreeMap::new();

        loop {
            let notification = notifications.recv().await?;
            if let RelayPoolNotification::Event { event, .. } = notification {
                if event.kind != Kind::Custom(ROUND1_RESPONSE_KIND) {
                    continue;
                }

                let response: Round1CommitmentResponse = serde_json::from_str(&event.content)?;
                if response.session_id != session_id {
                    continue;
                }
                if response.phase != "round1_commitment" {
                    continue;
                }

                let expected_pubkey = roster
                    .get(&response.participant_id)
                    .ok_or("response came from an unknown participant id")?;
                if &event.pubkey != expected_pubkey {
                    return Err::<Vec<AcceptedCommitment>, Box<dyn std::error::Error + Send + Sync>>(
                        "participant id did not match the Nostr event author".into(),
                    );
                }

                accepted
                    .entry(response.participant_id)
                    .or_insert(AcceptedCommitment {
                        participant_id: response.participant_id,
                        author: event.pubkey,
                        response,
                    });

                if accepted.len() >= threshold {
                    return Ok(accepted.into_values().collect::<Vec<_>>());
                }
            }
        }
    })
    .await?
}
