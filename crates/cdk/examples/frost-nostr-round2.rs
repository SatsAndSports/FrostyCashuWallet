#![allow(missing_docs)]

use std::collections::BTreeMap;
use std::env;
use std::time::Duration;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::prelude::FromHex;
use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
use cdk::nuts::SecretKey as CashuSecretKey;
use frost_secp256k1_tr as frost;
use nostr_sdk::{Client, EventBuilder, Filter, Keys, Kind, RelayPoolNotification, Tag, ToBech32};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

const ROUND1_REQUEST_KIND: u16 = 23102;
const ROUND1_RESPONSE_KIND: u16 = 23103;
const ROUND2_REQUEST_KIND: u16 = 23104;
const ROUND2_RESPONSE_KIND: u16 = 23105;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Round2Request {
    session_id: String,
    phase: String,
    selected_participant_ids: Vec<u16>,
    signing_package: frost::SigningPackage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Round2SignatureShareResponse {
    session_id: String,
    phase: String,
    participant_id: u16,
    signature_share: frost::round2::SignatureShare,
}

#[derive(Debug)]
struct AcceptedCommitment {
    participant_id: u16,
    author: nostr_sdk::PublicKey,
    response: Round1CommitmentResponse,
}

#[derive(Debug)]
struct AcceptedSignatureShare {
    participant_id: u16,
    author: nostr_sdk::PublicKey,
    response: Round2SignatureShareResponse,
}

#[derive(Debug)]
struct SignerRound2Outcome {
    participant_id: u16,
    commitment_event_id: nostr_sdk::EventId,
    signature_share_event_id: Option<nostr_sdk::EventId>,
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
    let timeout_secs = env_u64("NOSTR_ROUND2_TIMEOUT_SECS", DEFAULT_TIMEOUT_SECS)?;
    let coordinator_keys = match env::var("NOSTR_COORDINATOR_NSEC") {
        Ok(nsec) => Keys::parse(&nsec)?,
        Err(_) => Keys::generate(),
    };
    let signer_packages = dealer_signer_packages(&relay_url)?;
    let public_key_package = signer_packages
        .first()
        .ok_or("missing signer packages")?
        .public_key_package
        .clone();
    let session_id = format!("frost-round2-{}", uuid::Uuid::new_v4());
    let sig_all_message = format!("cashu-sigall-demo:{}:{}", session_id, "round2-over-nostr");
    let digest_hex = sha256::Hash::hash(sig_all_message.as_bytes()).to_string();
    let participant_ids = signer_packages
        .iter()
        .map(|package| package.participant_id)
        .collect::<Vec<_>>();
    let round1_request = Round1Request {
        session_id: session_id.clone(),
        phase: "round1_request".to_string(),
        sig_all_message,
        digest_hex: digest_hex.clone(),
        threshold: THRESHOLD,
        participant_ids,
    };

    println!("FROST Nostr round-2 demo");
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
            run_signer_round2(signer_package, coordinator_pubkey, request, ready_tx).await
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

    let round1_filter = Filter::new()
        .kind(Kind::Custom(ROUND1_RESPONSE_KIND))
        .identifier(session_id.clone());
    let round2_filter = Filter::new()
        .kind(Kind::Custom(ROUND2_RESPONSE_KIND))
        .identifier(session_id.clone());
    coordinator_client.subscribe(round1_filter, None).await?;
    coordinator_client.subscribe(round2_filter, None).await?;

    sleep(Duration::from_millis(250)).await;

    let round1_output = coordinator_client
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
        round1_output.id().to_bech32()?
    );

    let accepted_commitments = wait_for_round1_commitments(
        &coordinator_client,
        &session_id,
        &roster,
        THRESHOLD as usize,
        timeout_secs,
    )
    .await?;

    println!("\nAccepted round-1 commitments:");
    for accepted_commitment in &accepted_commitments {
        println!(
            "- participant {} via {}",
            accepted_commitment.participant_id,
            accepted_commitment.author.to_bech32()?
        );
    }

    let selected_participant_ids = accepted_commitments
        .iter()
        .map(|accepted_commitment| accepted_commitment.participant_id)
        .collect::<Vec<_>>();
    let commitments_map = accepted_commitments
        .into_iter()
        .map(|accepted_commitment| {
            let identifier = frost::Identifier::try_from(accepted_commitment.participant_id)?;
            Ok((identifier, accepted_commitment.response.commitments))
        })
        .collect::<DemoResult<BTreeMap<_, _>>>()?;
    let digest_bytes = <[u8; 32]>::from_hex(&digest_hex)?;
    let signing_package = frost::SigningPackage::new(commitments_map, &digest_bytes);
    let round2_request = Round2Request {
        session_id: session_id.clone(),
        phase: "round2_request".to_string(),
        selected_participant_ids: selected_participant_ids.clone(),
        signing_package: signing_package.clone(),
    };

    println!(
        "\nCoordinator selected signers: {:?}",
        selected_participant_ids
    );
    println!(
        "Round-2 request:\n{}",
        serde_json::to_string_pretty(&round2_request)?
    );

    let round2_output = coordinator_client
        .send_event_builder(
            EventBuilder::new(
                Kind::Custom(ROUND2_REQUEST_KIND),
                serde_json::to_string(&round2_request)?,
            )
            .tag(Tag::identifier(session_id.clone())),
        )
        .await?;
    println!(
        "Published round-2 request event: {}",
        round2_output.id().to_bech32()?
    );

    let accepted_signature_shares = wait_for_round2_signature_shares(
        &coordinator_client,
        &session_id,
        &roster,
        &selected_participant_ids,
        timeout_secs,
    )
    .await?;

    println!("\nAccepted round-2 signature shares:");
    for accepted_share in &accepted_signature_shares {
        println!(
            "- participant {} via {}",
            accepted_share.participant_id,
            accepted_share.author.to_bech32()?
        );
    }

    let signature_shares = accepted_signature_shares
        .into_iter()
        .map(|accepted_share| {
            let identifier = frost::Identifier::try_from(accepted_share.participant_id)?;
            Ok((identifier, accepted_share.response.signature_share))
        })
        .collect::<DemoResult<BTreeMap<_, _>>>()?;
    let group_signature =
        frost::aggregate(&signing_package, &signature_shares, &public_key_package)?;
    public_key_package
        .verifying_key()
        .verify(&digest_bytes, &group_signature)?;
    let signature = SchnorrSignature::from_slice(group_signature.serialize()?.as_slice())?;

    println!("\nAggregate Schnorr signature: {}", signature);
    println!("Signed digest hex: {}", digest_hex);

    coordinator_client.disconnect().await;

    for handle in signer_handles {
        let outcome = handle.await??;
        println!(
            "Signer {} published round-1 event: {}",
            outcome.participant_id,
            outcome.commitment_event_id.to_bech32()?
        );
        match outcome.signature_share_event_id {
            Some(event_id) => println!(
                "Signer {} published round-2 event: {}",
                outcome.participant_id,
                event_id.to_bech32()?
            ),
            None => println!(
                "Signer {} was not selected for round 2",
                outcome.participant_id
            ),
        }
    }

    println!("\nNostr round-2 demo succeeded");

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

async fn run_signer_round2(
    signer_package: DealerSignerPackage,
    coordinator_pubkey: nostr_sdk::PublicKey,
    request: Round1Request,
    ready_tx: mpsc::Sender<u16>,
) -> DemoResult<SignerRound2Outcome> {
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
    let round2_filter = Filter::new()
        .kind(Kind::Custom(ROUND2_REQUEST_KIND))
        .author(coordinator_pubkey)
        .identifier(request.session_id.clone());
    signer_client.subscribe(request_filter, None).await?;
    signer_client.subscribe(round2_filter, None).await?;

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
    let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut rng);

    let round1_response = Round1CommitmentResponse {
        session_id: incoming_request.session_id.clone(),
        phase: "round1_commitment".to_string(),
        participant_id: signer_package.participant_id,
        commitments,
    };
    let round1_output = signer_client
        .send_event_builder(
            EventBuilder::new(
                Kind::Custom(ROUND1_RESPONSE_KIND),
                serde_json::to_string(&round1_response)?,
            )
            .tag(Tag::identifier(request.session_id.clone())),
        )
        .await?;

    let round2_request = wait_for_round2_request(&signer_client, &request.session_id).await?;
    if round2_request.phase != "round2_request" {
        return Err("coordinator published an unexpected round-2 phase".into());
    }

    if !round2_request
        .selected_participant_ids
        .contains(&signer_package.participant_id)
    {
        signer_client.disconnect().await;

        return Ok(SignerRound2Outcome {
            participant_id: signer_package.participant_id,
            commitment_event_id: round1_output.id().clone(),
            signature_share_event_id: None,
        });
    }

    let expected_digest = <[u8; 32]>::from_hex(&request.digest_hex)?;
    if round2_request.signing_package.message() != &expected_digest.to_vec() {
        return Err("round-2 signing package used unexpected digest bytes".into());
    }
    let signer_identifier = frost::Identifier::try_from(signer_package.participant_id)?;
    if round2_request
        .signing_package
        .signing_commitment(&signer_identifier)
        .is_none()
    {
        return Err("round-2 signing package did not include signer commitment".into());
    }

    let signature_share =
        frost::round2::sign(&round2_request.signing_package, &nonces, &key_package)?;
    let round2_response = Round2SignatureShareResponse {
        session_id: request.session_id.clone(),
        phase: "round2_signature_share".to_string(),
        participant_id: signer_package.participant_id,
        signature_share,
    };
    let round2_output = signer_client
        .send_event_builder(
            EventBuilder::new(
                Kind::Custom(ROUND2_RESPONSE_KIND),
                serde_json::to_string(&round2_response)?,
            )
            .tag(Tag::identifier(request.session_id)),
        )
        .await?;

    signer_client.disconnect().await;

    Ok(SignerRound2Outcome {
        participant_id: signer_package.participant_id,
        commitment_event_id: round1_output.id().clone(),
        signature_share_event_id: Some(round2_output.id().clone()),
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

async fn wait_for_round2_request(client: &Client, session_id: &str) -> DemoResult<Round2Request> {
    let mut notifications = client.notifications();

    loop {
        let notification = notifications.recv().await?;
        if let RelayPoolNotification::Event { event, .. } = notification {
            if event.kind != Kind::Custom(ROUND2_REQUEST_KIND) {
                continue;
            }

            let request: Round2Request = serde_json::from_str(&event.content)?;
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
                if response.session_id != session_id || response.phase != "round1_commitment" {
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

async fn wait_for_round2_signature_shares(
    client: &Client,
    session_id: &str,
    roster: &BTreeMap<u16, nostr_sdk::PublicKey>,
    selected_participant_ids: &[u16],
    timeout_secs: u64,
) -> DemoResult<Vec<AcceptedSignatureShare>> {
    let mut notifications = client.notifications();

    timeout(Duration::from_secs(timeout_secs), async move {
        let mut accepted = BTreeMap::new();

        loop {
            let notification = notifications.recv().await?;
            if let RelayPoolNotification::Event { event, .. } = notification {
                if event.kind != Kind::Custom(ROUND2_RESPONSE_KIND) {
                    continue;
                }

                let response: Round2SignatureShareResponse = serde_json::from_str(&event.content)?;
                if response.session_id != session_id || response.phase != "round2_signature_share" {
                    continue;
                }
                if !selected_participant_ids.contains(&response.participant_id) {
                    return Err::<
                        Vec<AcceptedSignatureShare>,
                        Box<dyn std::error::Error + Send + Sync>,
                    >(
                        "received a round-2 signature share from a non-selected signer".into(),
                    );
                }

                let expected_pubkey = roster
                    .get(&response.participant_id)
                    .ok_or("response came from an unknown participant id")?;
                if &event.pubkey != expected_pubkey {
                    return Err::<
                        Vec<AcceptedSignatureShare>,
                        Box<dyn std::error::Error + Send + Sync>,
                    >(
                        "participant id did not match the Nostr event author".into()
                    );
                }

                accepted
                    .entry(response.participant_id)
                    .or_insert(AcceptedSignatureShare {
                        participant_id: response.participant_id,
                        author: event.pubkey,
                        response,
                    });

                if accepted.len() >= selected_participant_ids.len() {
                    return Ok(accepted.into_values().collect::<Vec<_>>());
                }
            }
        }
    })
    .await?
}
