use std::collections::BTreeMap;
use std::time::Duration;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
use cdk::nuts::{PublicKey as CashuPublicKey, SecretKey as CashuSecretKey};
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::keys::EvenY;
use nostr_sdk::{Client, EventBuilder, Filter, Keys, Kind, RelayPoolNotification, Tag, ToBech32};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

pub type DemoResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub const DEMO_SECRET_HEX: &str =
    "e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734";
pub const DEFAULT_NOSTR_RELAYS: &[&str] = &["ws://127.0.0.1:7777"];
pub const DEFAULT_MAX_SIGNERS: u16 = 3;
pub const DEFAULT_THRESHOLD: u16 = 2;

// ---------------------------------------------------------------------------
// Nostr event kinds
// ---------------------------------------------------------------------------

const SIGNER_PROVISIONED_KIND: u16 = 23100;
const ROUND1_REQUEST_KIND: u16 = 23102;
const ROUND1_RESPONSE_KIND: u16 = 23103;
const ROUND2_REQUEST_KIND: u16 = 23104;
const ROUND2_RESPONSE_KIND: u16 = 23105;

// ---------------------------------------------------------------------------
// Dealer setup (one-time key split)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct DealerSetup {
    pub provisioning_id: String,
    pub group_public_key: CashuPublicKey,
    pub max_signers: u16,
    pub threshold: u16,
    pub signer_packages: Vec<DealerSignerPackage>,
    pub roster: BTreeMap<u16, nostr_sdk::PublicKey>,
    pub public_key_package: frost::keys::PublicKeyPackage,
}

impl DealerSetup {
    /// Create a subset of this dealer setup containing only the given active
    /// signer IDs. The group public key and threshold remain the same.
    pub fn with_active_signers(&self, active_ids: &[u16]) -> Self {
        let signer_packages: Vec<DealerSignerPackage> = self
            .signer_packages
            .iter()
            .filter(|p| active_ids.contains(&p.participant_id))
            .cloned()
            .collect();
        let roster: BTreeMap<u16, nostr_sdk::PublicKey> = self
            .roster
            .iter()
            .filter(|(id, _)| active_ids.contains(id))
            .map(|(id, pk)| (*id, *pk))
            .collect();

        Self {
            provisioning_id: self.provisioning_id.clone(),
            group_public_key: self.group_public_key,
            max_signers: active_ids.len() as u16,
            threshold: self.threshold,
            signer_packages,
            roster,
            public_key_package: self.public_key_package.clone(),
        }
    }
}

pub fn dealer_setup(
    source_secret: &CashuSecretKey,
    relays: &[String],
    max_signers: u16,
    threshold: u16,
) -> DemoResult<DealerSetup> {
    let provisioning_id = format!("prov-{}", uuid::Uuid::new_v4());
    let frost_signing_key = frost::SigningKey::deserialize(source_secret.as_secret_bytes())?;
    let mut rng = frost::rand_core::OsRng;
    let (secret_shares, public_key_package) = frost::keys::split(
        &frost_signing_key,
        max_signers,
        threshold,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )?;

    let mut signer_packages = Vec::new();
    for (index, (_identifier, secret_share)) in secret_shares.into_iter().enumerate() {
        let participant_id = (index as u16) + 1;
        let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
        let expected_identifier = frost::Identifier::try_from(participant_id)?;
        if key_package.identifier() != &expected_identifier {
            return Err("dealer produced unexpected participant identifier ordering".into());
        }

        let nostr_keys = Keys::generate();
        signer_packages.push(DealerSignerPackage {
            provisioning_id: provisioning_id.clone(),
            participant_id,
            nostr_nsec: nostr_keys.secret_key().to_bech32()?,
            relays: relays.to_vec(),
            key_package,
            public_key_package: public_key_package.clone(),
        });
    }

    let roster = signer_packages
        .iter()
        .map(|package| {
            let keys = Keys::parse(&package.nostr_nsec)?;
            Ok((package.participant_id, keys.public_key()))
        })
        .collect::<DemoResult<BTreeMap<_, _>>>()?;

    let group_public_key =
        frost_verifying_key_to_cashu_public_key(public_key_package.verifying_key())?;

    Ok(DealerSetup {
        provisioning_id,
        group_public_key,
        max_signers,
        threshold,
        signer_packages,
        roster,
        public_key_package,
    })
}

fn frost_verifying_key_to_cashu_public_key(
    verifying_key: &frost::VerifyingKey,
) -> DemoResult<CashuPublicKey> {
    let verifying_key = (*verifying_key).into_even_y(None);
    let verifying_key_bytes = verifying_key.serialize()?;
    Ok(CashuPublicKey::from_slice(verifying_key_bytes.as_slice())?)
}

// ---------------------------------------------------------------------------
// Nostr protocol types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct NostrFrostCoordinatorConfig {
    pub relays: Vec<String>,
    pub coordinator_keys: Keys,
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
    pub provisioning_id: String,
    pub participant_id: u16,
    pub nostr_nsec: String,
    pub relays: Vec<String>,
    pub key_package: frost::keys::KeyPackage,
    pub public_key_package: frost::keys::PublicKeyPackage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignerProvisionedResponse {
    provisioning_id: String,
    participant_id: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Round1Request {
    session_id: String,
    phase: String,
    signable_message: String,
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

struct AcceptedCommitment {
    participant_id: u16,
    commitments: frost::round1::SigningCommitments,
}

struct AcceptedSignatureShare {
    participant_id: u16,
    signature_share: frost::round2::SignatureShare,
}

// ---------------------------------------------------------------------------
// Provisioning (one-off, before any session)
// ---------------------------------------------------------------------------

/// Provisioned signer group: signer tasks are running and have acknowledged
/// receipt of their packages over Nostr.
pub struct ProvisionedSigners {
    signer_handles: Vec<tokio::task::JoinHandle<DemoResult<()>>>,
}

impl ProvisionedSigners {
    /// Shut down all signer tasks. Call this when the demo is done.
    pub async fn shutdown(self) -> DemoResult<()> {
        for handle in self.signer_handles {
            handle.abort();
        }
        Ok(())
    }
}

/// Wait for external signers (e.g. web app participants) to acknowledge their
/// packages over Nostr (Kind 23100). Does not spawn any local signer tasks.
/// Use this in `--interactive` mode where signers are real people.
///
/// The coordinator can press Enter at any time once at least `threshold`
/// signers have joined to proceed with only the active subset.
///
/// Returns the `ProvisionedSigners` handle and the list of participant IDs
/// that actually joined.
pub async fn wait_for_external_signers(
    dealer: &DealerSetup,
    coordinator_config: &NostrFrostCoordinatorConfig,
) -> DemoResult<(ProvisionedSigners, Vec<u16>)> {
    let coordinator_client = Client::new(coordinator_config.coordinator_keys.clone());
    for relay in &coordinator_config.relays {
        coordinator_client.add_relay(relay.as_str()).await?;
    }
    coordinator_client.connect().await;

    let provisioned_filter = Filter::new()
        .kind(Kind::Custom(SIGNER_PROVISIONED_KIND))
        .identifier(dealer.provisioning_id.clone());
    coordinator_client
        .subscribe(provisioned_filter, None)
        .await?;

    sleep(Duration::from_millis(250)).await;

    let active_ids = wait_for_provisioned_interactive(
        &coordinator_client,
        &dealer.provisioning_id,
        &dealer.roster,
        dealer.max_signers as usize,
        dealer.threshold as usize,
    )
    .await?;

    coordinator_client.disconnect().await;

    Ok((
        ProvisionedSigners {
            signer_handles: Vec::new(),
        },
        active_ids,
    ))
}

/// Interactive provisioning: collects join events from the relay while also
/// listening for Enter on stdin. When Enter is pressed and at least
/// `threshold` signers have joined, returns the active participant IDs.
async fn wait_for_provisioned_interactive(
    coordinator_client: &Client,
    provisioning_id: &str,
    roster: &BTreeMap<u16, nostr_sdk::PublicKey>,
    total: usize,
    threshold: usize,
) -> DemoResult<Vec<u16>> {
    let mut notifications = coordinator_client.notifications();
    let mut acked = BTreeMap::<u16, ()>::new();

    // Spawn a task that resolves when stdin receives a line (Enter pressed)
    let (enter_tx, mut enter_rx) = tokio::sync::mpsc::channel::<()>(1);
    tokio::spawn(async move {
        let mut buf = String::new();
        let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
        let _ = tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut buf).await;
        let _ = enter_tx.send(()).await;
    });

    loop {
        tokio::select! {
            notification = notifications.recv() => {
                let notification = notification?;
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind != Kind::Custom(SIGNER_PROVISIONED_KIND) {
                        continue;
                    }

                    let response: SignerProvisionedResponse =
                        serde_json::from_str(&event.content)?;
                    if response.provisioning_id != provisioning_id {
                        continue;
                    }

                    let expected_pubkey = roster
                        .get(&response.participant_id)
                        .ok_or("provisioned ack from unknown participant id")?;
                    if &event.pubkey != expected_pubkey {
                        return Err(
                            "participant id did not match the Nostr event author".into(),
                        );
                    }

                    if !acked.contains_key(&response.participant_id) {
                        acked.insert(response.participant_id, ());
                        let count = acked.len();
                        if count >= threshold {
                            println!(
                                "Signer {} joined! ({}/{} ready) -- THRESHOLD MET, press ENTER to start",
                                response.participant_id, count, total,
                            );
                        } else {
                            println!(
                                "Signer {} joined! ({}/{} ready, need {} for threshold)",
                                response.participant_id, count, total, threshold,
                            );
                        }
                    }
                }
            }
            _ = enter_rx.recv() => {
                let count = acked.len();
                if count >= threshold {
                    println!(
                        "Proceeding with {}/{} signers.",
                        count, total,
                    );
                    return Ok(acked.into_keys().collect());
                }
                println!(
                    "Cannot proceed: only {}/{} signers ready (need at least {}).",
                    count, total, threshold,
                );
                // Re-spawn the stdin listener for another Enter press
                let (new_tx, new_rx) = tokio::sync::mpsc::channel::<()>(1);
                enter_rx = new_rx;
                tokio::spawn(async move {
                    let mut buf = String::new();
                    let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
                    let _ = tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut buf).await;
                    let _ = new_tx.send(()).await;
                });
            }
        }
    }
}

/// Spawn signer tasks and wait for each one to acknowledge its package over
/// Nostr (Kind 23100). This is a one-off step before any signing session.
pub async fn provision_signers(
    dealer: &DealerSetup,
    coordinator_config: &NostrFrostCoordinatorConfig,
) -> DemoResult<ProvisionedSigners> {
    let coordinator_client = Client::new(coordinator_config.coordinator_keys.clone());
    for relay in &coordinator_config.relays {
        coordinator_client.add_relay(relay.as_str()).await?;
    }
    coordinator_client.connect().await;

    let provisioned_filter = Filter::new()
        .kind(Kind::Custom(SIGNER_PROVISIONED_KIND))
        .identifier(dealer.provisioning_id.clone());
    coordinator_client
        .subscribe(provisioned_filter, None)
        .await?;

    sleep(Duration::from_millis(250)).await;

    let coordinator_pubkey = coordinator_config.coordinator_keys.public_key();
    let mut signer_handles = Vec::new();

    for signer_package in dealer.signer_packages.clone() {
        let coordinator_pubkey = coordinator_pubkey;
        let relays = coordinator_config.relays.clone();
        signer_handles.push(tokio::spawn(async move {
            run_signer(signer_package, coordinator_pubkey, relays).await
        }));
    }

    wait_for_provisioned_acks(
        &coordinator_client,
        &dealer.provisioning_id,
        &dealer.roster,
        dealer.max_signers as usize,
    )
    .await?;

    coordinator_client.disconnect().await;

    Ok(ProvisionedSigners { signer_handles })
}

async fn wait_for_provisioned_acks(
    coordinator_client: &Client,
    provisioning_id: &str,
    roster: &BTreeMap<u16, nostr_sdk::PublicKey>,
    expected_count: usize,
) -> DemoResult<Vec<u16>> {
    let mut notifications = coordinator_client.notifications();
    let mut acked = BTreeMap::new();

    loop {
        let notification = notifications.recv().await?;
        if let RelayPoolNotification::Event { event, .. } = notification {
            if event.kind != Kind::Custom(SIGNER_PROVISIONED_KIND) {
                continue;
            }

            let response: SignerProvisionedResponse = serde_json::from_str(&event.content)?;
            if response.provisioning_id != provisioning_id {
                continue;
            }

            let expected_pubkey = roster
                .get(&response.participant_id)
                .ok_or("provisioned ack from unknown participant id")?;
            if &event.pubkey != expected_pubkey {
                return Err("participant id did not match the Nostr event author".into());
            }

            if !acked.contains_key(&response.participant_id) {
                acked.insert(response.participant_id, ());
                println!(
                    "Signer {} joined! ({}/{} ready)",
                    response.participant_id,
                    acked.len(),
                    expected_count,
                );
            }

            if acked.len() >= expected_count {
                return Ok(acked.into_keys().collect::<Vec<_>>());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Signing session (per operation)
// ---------------------------------------------------------------------------

pub async fn sign_message_via_nostr(
    dealer: &DealerSetup,
    signable_message: &str,
    config: &NostrFrostCoordinatorConfig,
) -> DemoResult<NostrFrostSigningResult> {
    let digest = sha256::Hash::hash(signable_message.as_bytes());
    let digest_bytes = *digest.as_byte_array();
    let session_id = config
        .session_id
        .clone()
        .unwrap_or_else(|| format!("{}-{}", config.session_prefix, uuid::Uuid::new_v4()));
    let participant_ids = dealer
        .signer_packages
        .iter()
        .map(|p| p.participant_id)
        .collect::<Vec<_>>();
    let round1_request = Round1Request {
        session_id: session_id.clone(),
        phase: "round1_request".to_string(),
        signable_message: signable_message.to_string(),
        digest_hex: digest.to_string(),
        threshold: dealer.threshold,
        participant_ids,
    };

    let coordinator_client = connect_coordinator(config, &session_id).await?;

    let accepted_commitments = run_coordinator_round1(
        &coordinator_client,
        &session_id,
        &round1_request,
        &dealer.roster,
        dealer.threshold as usize,
    )
    .await?;
    let (selected_participant_ids, signing_package) =
        build_signing_package(accepted_commitments, &digest_bytes)?;

    let accepted_shares = run_coordinator_round2(
        &coordinator_client,
        &session_id,
        &selected_participant_ids,
        &signing_package,
        &dealer.roster,
    )
    .await?;

    let signature_hex = aggregate_signature(
        &signing_package,
        accepted_shares,
        &dealer.public_key_package,
        &digest_bytes,
    )?;

    coordinator_client.disconnect().await;

    Ok(NostrFrostSigningResult {
        session_id,
        selected_participant_ids,
        signature_hex,
    })
}

// ---------------------------------------------------------------------------
// Coordinator helpers
// ---------------------------------------------------------------------------

async fn connect_coordinator(
    config: &NostrFrostCoordinatorConfig,
    session_id: &str,
) -> DemoResult<Client> {
    let coordinator_client = Client::new(config.coordinator_keys.clone());
    for relay in &config.relays {
        coordinator_client.add_relay(relay.as_str()).await?;
    }
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

async fn run_coordinator_round1(
    coordinator_client: &Client,
    session_id: &str,
    round1_request: &Round1Request,
    roster: &BTreeMap<u16, nostr_sdk::PublicKey>,
    threshold: usize,
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
    )
    .await
}

fn build_signing_package(
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

async fn run_coordinator_round2(
    coordinator_client: &Client,
    session_id: &str,
    selected_participant_ids: &[u16],
    signing_package: &frost::SigningPackage,
    roster: &BTreeMap<u16, nostr_sdk::PublicKey>,
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
    )
    .await
}

fn aggregate_signature(
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

// ---------------------------------------------------------------------------
// Signer task (persistent: acks once, then handles signing sessions)
// ---------------------------------------------------------------------------

async fn run_signer(
    signer_package: DealerSignerPackage,
    coordinator_pubkey: nostr_sdk::PublicKey,
    relays: Vec<String>,
) -> DemoResult<()> {
    let signer_keys = Keys::parse(&signer_package.nostr_nsec)?;
    let signer_client = Client::new(signer_keys);
    for relay in &relays {
        signer_client.add_relay(relay.as_str()).await?;
    }
    signer_client.connect().await;

    // Subscribe to all coordinator requests (any session)
    let round1_filter = Filter::new()
        .kind(Kind::Custom(ROUND1_REQUEST_KIND))
        .author(coordinator_pubkey);
    let round2_filter = Filter::new()
        .kind(Kind::Custom(ROUND2_REQUEST_KIND))
        .author(coordinator_pubkey);
    signer_client.subscribe(round1_filter, None).await?;
    signer_client.subscribe(round2_filter, None).await?;

    // Acknowledge provisioning (one-off)
    let provisioned = SignerProvisionedResponse {
        provisioning_id: signer_package.provisioning_id.clone(),
        participant_id: signer_package.participant_id,
    };
    signer_client
        .send_event_builder(
            EventBuilder::new(
                Kind::Custom(SIGNER_PROVISIONED_KIND),
                serde_json::to_string(&provisioned)?,
            )
            .tag(Tag::identifier(signer_package.provisioning_id.clone())),
        )
        .await?;

    // Enter the signing loop: handle sessions until the task is aborted
    loop {
        match handle_one_session(&signer_client, &signer_package).await {
            Ok(()) => {}
            Err(e) => {
                // If the task was cancelled (e.g. shutdown), break cleanly
                let msg = e.to_string();
                if msg.contains("closed") || msg.contains("cancelled") {
                    break;
                }
                return Err(e);
            }
        }
    }

    signer_client.disconnect().await;
    Ok(())
}

async fn handle_one_session(
    signer_client: &Client,
    signer_package: &DealerSignerPackage,
) -> DemoResult<()> {
    // Wait for a round-1 request from the coordinator
    let incoming_request = wait_for_any_round1_request(signer_client).await?;
    if !incoming_request
        .participant_ids
        .contains(&signer_package.participant_id)
    {
        return Ok(()); // Not addressed to us, skip
    }

    let session_id = incoming_request.session_id.clone();

    // Generate commitments
    let mut rng = frost::rand_core::OsRng;
    let (nonces, commitments) =
        frost::round1::commit(signer_package.key_package.signing_share(), &mut rng);

    let round1_response = Round1CommitmentResponse {
        session_id: session_id.clone(),
        phase: "round1_commitment".to_string(),
        participant_id: signer_package.participant_id,
        commitments,
    };
    signer_client
        .send_event_builder(
            EventBuilder::new(
                Kind::Custom(ROUND1_RESPONSE_KIND),
                serde_json::to_string(&round1_response)?,
            )
            .tag(Tag::identifier(session_id.clone())),
        )
        .await?;

    // Wait for the round-2 request
    let round2_request = wait_for_round2_request(signer_client, &session_id).await?;
    if !round2_request
        .selected_participant_ids
        .contains(&signer_package.participant_id)
    {
        return Ok(()); // Not selected for this session
    }

    let signer_identifier = frost::Identifier::try_from(signer_package.participant_id)?;
    if round2_request
        .signing_package
        .signing_commitment(&signer_identifier)
        .is_none()
    {
        return Err("round-2 signing package did not include signer commitment".into());
    }

    let signature_share = frost::round2::sign(
        &round2_request.signing_package,
        &nonces,
        &signer_package.key_package,
    )?;
    let round2_response = Round2SignatureShareResponse {
        session_id: session_id.clone(),
        phase: "round2_signature_share".to_string(),
        participant_id: signer_package.participant_id,
        signature_share,
    };
    signer_client
        .send_event_builder(
            EventBuilder::new(
                Kind::Custom(ROUND2_RESPONSE_KIND),
                serde_json::to_string(&round2_response)?,
            )
            .tag(Tag::identifier(session_id)),
        )
        .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Nostr message waiters
// ---------------------------------------------------------------------------

/// Wait for any round-1 request from the coordinator (not session-specific).
async fn wait_for_any_round1_request(client: &Client) -> DemoResult<Round1Request> {
    let mut notifications = client.notifications();
    loop {
        let notification = notifications.recv().await?;
        if let RelayPoolNotification::Event { event, .. } = notification {
            if event.kind != Kind::Custom(ROUND1_REQUEST_KIND) {
                continue;
            }
            let request: Round1Request = serde_json::from_str(&event.content)?;
            return Ok(request);
        }
    }
}

/// Wait for a round-2 request for a specific session.
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
) -> DemoResult<Vec<AcceptedCommitment>> {
    let mut notifications = client.notifications();
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
                return Err("participant id did not match the Nostr event author".into());
            }
            if !accepted.contains_key(&response.participant_id) {
                println!(
                    "Signer {} committed nonces ({}/{} received)",
                    response.participant_id,
                    accepted.len() + 1,
                    threshold,
                );
                accepted.insert(response.participant_id, AcceptedCommitment {
                    participant_id: response.participant_id,
                    commitments: response.commitments,
                });
            }
            if accepted.len() >= threshold {
                return Ok(accepted.into_values().collect::<Vec<_>>());
            }
        }
    }
}

async fn wait_for_round2_signature_shares(
    client: &Client,
    session_id: &str,
    roster: &BTreeMap<u16, nostr_sdk::PublicKey>,
    selected_participant_ids: &[u16],
) -> DemoResult<Vec<AcceptedSignatureShare>> {
    let mut notifications = client.notifications();
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
                return Err(
                    "received a round-2 signature share from a non-selected signer".into(),
                );
            }
            let expected_pubkey = roster
                .get(&response.participant_id)
                .ok_or("response came from an unknown participant id")?;
            if &event.pubkey != expected_pubkey {
                return Err(
                    "participant id did not match the Nostr event author".into(),
                );
            }
            if !accepted.contains_key(&response.participant_id) {
                println!(
                    "Signer {} published signature share ({}/{} received)",
                    response.participant_id,
                    accepted.len() + 1,
                    selected_participant_ids.len(),
                );
                accepted.insert(response.participant_id, AcceptedSignatureShare {
                    participant_id: response.participant_id,
                    signature_share: response.signature_share,
                });
            }
            if accepted.len() >= selected_participant_ids.len() {
                return Ok(accepted.into_values().collect::<Vec<_>>());
            }
        }
    }
}
