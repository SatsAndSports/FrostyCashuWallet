use std::collections::BTreeMap;
use std::time::Duration;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
use cdk::nuts::SecretKey as CashuSecretKey;
use frost_secp256k1_tr as frost;
use nostr_sdk::{Client, EventBuilder, Filter, Keys, Kind, RelayPoolNotification, Tag, ToBech32};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

pub type DemoResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningPhase {
    Round1,
    Round2,
}

pub const DEMO_SECRET_HEX: &str =
    "e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734";
pub const DEFAULT_NOSTR_RELAY_URL: &str = "ws://127.0.0.1:7777";
pub const DEFAULT_NOSTR_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_MAX_SIGNERS: u16 = 3;
pub const DEFAULT_THRESHOLD: u16 = 2;

const ROUND1_REQUEST_KIND: u16 = 23102;
const ROUND1_RESPONSE_KIND: u16 = 23103;
const ROUND2_REQUEST_KIND: u16 = 23104;
const ROUND2_RESPONSE_KIND: u16 = 23105;

#[derive(Debug, Clone)]
pub struct NostrFrostCoordinatorConfig {
    pub relay_url: String,
    pub coordinator_keys: Keys,
    pub timeout_secs: u64,
    pub max_signers: u16,
    pub threshold: u16,
    pub session_id: Option<String>,
    pub session_prefix: String,
}

#[derive(Debug, Clone)]
pub struct NostrFrostSigningResult {
    pub session_id: String,
    pub selected_participant_ids: Vec<u16>,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DealerSignerPackage {
    pub participant_id: u16,
    pub nostr_nsec: String,
    pub relay_url: String,
    pub key_package: frost::keys::KeyPackage,
    pub public_key_package: frost::keys::PublicKeyPackage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round1Request {
    pub session_id: String,
    pub phase: String,
    pub signable_message: String,
    pub digest_hex: String,
    pub threshold: u16,
    pub participant_ids: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round1CommitmentResponse {
    pub session_id: String,
    pub phase: String,
    pub participant_id: u16,
    pub commitments: frost::round1::SigningCommitments,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round2Request {
    pub session_id: String,
    pub phase: String,
    pub selected_participant_ids: Vec<u16>,
    pub signing_package: frost::SigningPackage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round2SignatureShareResponse {
    pub session_id: String,
    pub phase: String,
    pub participant_id: u16,
    pub signature_share: frost::round2::SignatureShare,
}

#[derive(Debug)]
pub struct AcceptedCommitment {
    pub participant_id: u16,
    pub author: nostr_sdk::PublicKey,
    pub commitments: frost::round1::SigningCommitments,
}

#[derive(Debug)]
pub struct AcceptedSignatureShare {
    pub participant_id: u16,
    pub author: nostr_sdk::PublicKey,
    pub signature_share: frost::round2::SignatureShare,
}

#[derive(Debug)]
pub struct SignerOutcome {
    pub participant_id: u16,
    pub commitment_event_id: nostr_sdk::EventId,
    pub signature_share_event_id: Option<nostr_sdk::EventId>,
}

pub fn dealer_signer_packages(
    source_secret: &CashuSecretKey,
    relay_url: &str,
    max_signers: u16,
    threshold: u16,
) -> DemoResult<Vec<DealerSignerPackage>> {
    let frost_signing_key = frost::SigningKey::deserialize(source_secret.as_secret_bytes())?;
    let mut rng = frost::rand_core::OsRng;
    let (secret_shares, public_key_package) = frost::keys::split(
        &frost_signing_key,
        max_signers,
        threshold,
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

pub fn build_roster(
    signer_packages: &[DealerSignerPackage],
) -> DemoResult<BTreeMap<u16, nostr_sdk::PublicKey>> {
    signer_packages
        .iter()
        .map(|package| {
            let keys = Keys::parse(&package.nostr_nsec)?;
            Ok((package.participant_id, keys.public_key()))
        })
        .collect::<DemoResult<BTreeMap<_, _>>>()
}

pub async fn spawn_signers(
    signer_packages: Vec<DealerSignerPackage>,
    coordinator_pubkey: nostr_sdk::PublicKey,
    round1_request: Round1Request,
    phase: SigningPhase,
) -> DemoResult<(
    mpsc::Receiver<u16>,
    Vec<tokio::task::JoinHandle<DemoResult<SignerOutcome>>>,
)> {
    let max_signers = signer_packages.len();
    let (ready_tx, ready_rx) = mpsc::channel::<u16>(max_signers);
    let mut handles = Vec::new();

    for signer_package in signer_packages {
        let ready_tx = ready_tx.clone();
        let coordinator_pubkey = coordinator_pubkey;
        let request = round1_request.clone();
        handles.push(tokio::spawn(async move {
            run_signer(signer_package, coordinator_pubkey, request, ready_tx, phase).await
        }));
    }
    drop(ready_tx);

    Ok((ready_rx, handles))
}

pub async fn wait_for_all_signers_ready(
    ready_rx: &mut mpsc::Receiver<u16>,
    count: u16,
) -> DemoResult<()> {
    for _ in 0..count {
        ready_rx
            .recv()
            .await
            .ok_or("failed to wait for signer readiness")?;
    }
    Ok(())
}

pub async fn run_coordinator_round1(
    coordinator_client: &Client,
    session_id: &str,
    round1_request: &Round1Request,
    roster: &BTreeMap<u16, nostr_sdk::PublicKey>,
    threshold: usize,
    timeout_secs: u64,
) -> DemoResult<Vec<AcceptedCommitment>> {
    coordinator_client
        .send_event_builder(
            EventBuilder::new(
                Kind::Custom(ROUND1_REQUEST_KIND),
                serde_json::to_string(round1_request)?,
            )
            .tag(Tag::identifier(session_id.to_string())),
        )
        .await?;

    wait_for_round1_commitments(
        coordinator_client,
        session_id,
        roster,
        threshold,
        timeout_secs,
    )
    .await
}

pub fn build_signing_package(
    accepted: Vec<AcceptedCommitment>,
    digest_bytes: &[u8; 32],
) -> DemoResult<(Vec<u16>, frost::SigningPackage)> {
    let selected_ids = accepted
        .iter()
        .map(|a| a.participant_id)
        .collect::<Vec<_>>();
    let commitments_map = accepted
        .into_iter()
        .map(|a| {
            let identifier = frost::Identifier::try_from(a.participant_id)?;
            Ok((identifier, a.commitments))
        })
        .collect::<DemoResult<BTreeMap<_, _>>>()?;
    let signing_package = frost::SigningPackage::new(commitments_map, digest_bytes);
    Ok((selected_ids, signing_package))
}

pub async fn run_coordinator_round2(
    coordinator_client: &Client,
    session_id: &str,
    selected_participant_ids: &[u16],
    signing_package: &frost::SigningPackage,
    roster: &BTreeMap<u16, nostr_sdk::PublicKey>,
    timeout_secs: u64,
) -> DemoResult<Vec<AcceptedSignatureShare>> {
    let round2_request = Round2Request {
        session_id: session_id.to_string(),
        phase: "round2_request".to_string(),
        selected_participant_ids: selected_participant_ids.to_vec(),
        signing_package: signing_package.clone(),
    };

    coordinator_client
        .send_event_builder(
            EventBuilder::new(
                Kind::Custom(ROUND2_REQUEST_KIND),
                serde_json::to_string(&round2_request)?,
            )
            .tag(Tag::identifier(session_id.to_string())),
        )
        .await?;

    wait_for_round2_signature_shares(
        coordinator_client,
        session_id,
        roster,
        selected_participant_ids,
        timeout_secs,
    )
    .await
}

pub fn aggregate_signature(
    signing_package: &frost::SigningPackage,
    accepted_shares: Vec<AcceptedSignatureShare>,
    public_key_package: &frost::keys::PublicKeyPackage,
    digest_bytes: &[u8; 32],
) -> DemoResult<String> {
    let signature_shares = accepted_shares
        .into_iter()
        .map(|a| {
            let identifier = frost::Identifier::try_from(a.participant_id)?;
            Ok((identifier, a.signature_share))
        })
        .collect::<DemoResult<BTreeMap<_, _>>>()?;
    let group_signature = frost::aggregate(signing_package, &signature_shares, public_key_package)?;
    public_key_package
        .verifying_key()
        .verify(digest_bytes, &group_signature)?;
    let signature = SchnorrSignature::from_slice(group_signature.serialize()?.as_slice())?;
    Ok(signature.to_string())
}

pub async fn connect_coordinator(
    config: &NostrFrostCoordinatorConfig,
    session_id: &str,
) -> DemoResult<Client> {
    let coordinator_client = Client::new(config.coordinator_keys.clone());
    coordinator_client
        .add_relay(config.relay_url.as_str())
        .await?;
    coordinator_client.connect().await;

    let round1_filter = Filter::new()
        .kind(Kind::Custom(ROUND1_RESPONSE_KIND))
        .identifier(session_id.to_string());
    let round2_filter = Filter::new()
        .kind(Kind::Custom(ROUND2_RESPONSE_KIND))
        .identifier(session_id.to_string());
    coordinator_client.subscribe(round1_filter, None).await?;
    coordinator_client.subscribe(round2_filter, None).await?;

    sleep(Duration::from_millis(250)).await;

    Ok(coordinator_client)
}

pub async fn sign_message_via_nostr(
    source_secret: &CashuSecretKey,
    signable_message: &str,
    config: &NostrFrostCoordinatorConfig,
) -> DemoResult<NostrFrostSigningResult> {
    let digest = sha256::Hash::hash(signable_message.as_bytes());
    let digest_bytes = *digest.as_byte_array();
    let signer_packages = dealer_signer_packages(
        source_secret,
        &config.relay_url,
        config.max_signers,
        config.threshold,
    )?;
    let public_key_package = signer_packages
        .first()
        .ok_or("missing signer packages")?
        .public_key_package
        .clone();
    let session_id = config
        .session_id
        .clone()
        .unwrap_or_else(|| format!("{}-{}", config.session_prefix, uuid::Uuid::new_v4()));
    let participant_ids = signer_packages
        .iter()
        .map(|p| p.participant_id)
        .collect::<Vec<_>>();
    let round1_request = Round1Request {
        session_id: session_id.clone(),
        phase: "round1_request".to_string(),
        signable_message: signable_message.to_string(),
        digest_hex: digest.to_string(),
        threshold: config.threshold,
        participant_ids,
    };
    let roster = build_roster(&signer_packages)?;

    let (mut ready_rx, signer_handles) = spawn_signers(
        signer_packages,
        config.coordinator_keys.public_key(),
        round1_request.clone(),
        SigningPhase::Round2,
    )
    .await?;
    wait_for_all_signers_ready(&mut ready_rx, config.max_signers).await?;

    let coordinator_client = connect_coordinator(config, &session_id).await?;

    let accepted_commitments = run_coordinator_round1(
        &coordinator_client,
        &session_id,
        &round1_request,
        &roster,
        config.threshold as usize,
        config.timeout_secs,
    )
    .await?;
    let (selected_participant_ids, signing_package) =
        build_signing_package(accepted_commitments, &digest_bytes)?;

    let accepted_shares = run_coordinator_round2(
        &coordinator_client,
        &session_id,
        &selected_participant_ids,
        &signing_package,
        &roster,
        config.timeout_secs,
    )
    .await?;

    let signature_hex = aggregate_signature(
        &signing_package,
        accepted_shares,
        &public_key_package,
        &digest_bytes,
    )?;

    coordinator_client.disconnect().await;

    for handle in signer_handles {
        handle.await??;
    }

    Ok(NostrFrostSigningResult {
        session_id,
        selected_participant_ids,
        signature_hex,
    })
}

async fn run_signer(
    signer_package: DealerSignerPackage,
    coordinator_pubkey: nostr_sdk::PublicKey,
    request: Round1Request,
    ready_tx: mpsc::Sender<u16>,
    phase: SigningPhase,
) -> DemoResult<SignerOutcome> {
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
    if phase == SigningPhase::Round2 {
        let round2_filter = Filter::new()
            .kind(Kind::Custom(ROUND2_REQUEST_KIND))
            .author(coordinator_pubkey)
            .identifier(request.session_id.clone());
        signer_client.subscribe(round2_filter, None).await?;
    }

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

    if phase == SigningPhase::Round1 {
        signer_client.disconnect().await;
        return Ok(SignerOutcome {
            participant_id: signer_package.participant_id,
            commitment_event_id: round1_output.id().clone(),
            signature_share_event_id: None,
        });
    }

    let round2_request = wait_for_round2_request(&signer_client, &request.session_id).await?;
    if !round2_request
        .selected_participant_ids
        .contains(&signer_package.participant_id)
    {
        signer_client.disconnect().await;
        return Ok(SignerOutcome {
            participant_id: signer_package.participant_id,
            commitment_event_id: round1_output.id().clone(),
            signature_share_event_id: None,
        });
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

    Ok(SignerOutcome {
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
                        commitments: response.commitments,
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
                        signature_share: response.signature_share,
                    });
                if accepted.len() >= selected_participant_ids.len() {
                    return Ok(accepted.into_values().collect::<Vec<_>>());
                }
            }
        }
    })
    .await?
}
