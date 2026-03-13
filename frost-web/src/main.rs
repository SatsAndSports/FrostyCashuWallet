use frost_secp256k1_tr as frost;
use leptos::prelude::*;
use leptos::task::spawn_local;
use nostr_sdk::{Client, EventBuilder, Filter, Kind, RelayPoolNotification, Tag};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants (must match the CLI coordinator in frost_nostr.rs)
// ---------------------------------------------------------------------------

const SIGNER_PROVISIONED_KIND: u16 = 23100;
const ROUND1_REQUEST_KIND: u16 = 23102;
const ROUND1_RESPONSE_KIND: u16 = 23103;
const ROUND2_REQUEST_KIND: u16 = 23104;
const ROUND2_RESPONSE_KIND: u16 = 23105;

// ---------------------------------------------------------------------------
// Protocol types (must match the CLI coordinator serialization)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum SignerState {
    /// Waiting for user to paste JSON package
    WaitingForPackage,
    /// Package parsed, ready to connect
    ReadyToJoin,
    /// Connected and sent Kind 23100, waiting for coordinator
    Joined,
    /// Round 1 request received, waiting for user to commit
    Round1ActionRequired,
    /// Commitments sent, waiting for round 2
    Round1Committed,
    /// Round 2 request received, waiting for user to sign
    Round2ActionRequired,
    /// Signature share sent
    Complete,
    /// Error state
    Error(String),
}

// ---------------------------------------------------------------------------
// Log entry type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct LogEntry {
    tag: String,
    message: String,
}

// ---------------------------------------------------------------------------
// Leptos App
// ---------------------------------------------------------------------------

fn main() {
    leptos::mount::mount_to_body(App);
}

#[component]
fn App() -> impl IntoView {
    let (state, set_state) = signal(SignerState::WaitingForPackage);
    let (log_entries, set_log_entries) = signal(Vec::<LogEntry>::new());
    let (package_json, set_package_json) = signal(String::new());
    let (package, set_package) = signal(None::<DealerSignerPackage>);
    let (client_store, set_client_store) = signal(None::<Client>);
    let (nonces_store, set_nonces_store) = signal(None::<frost::round1::SigningNonces>);
    let (round1_req, set_round1_req) = signal(None::<Round1Request>);
    let (round2_req, set_round2_req) = signal(None::<Round2Request>);
    let (session_id_store, set_session_id_store) = signal(None::<String>);

    let add_log = move |tag: &str, msg: &str| {
        set_log_entries.update(|entries| {
            entries.push(LogEntry {
                tag: tag.to_string(),
                message: msg.to_string(),
            });
        });
    };

    // Parse JSON handler
    let on_parse = move |_| {
        let json_str = package_json.get_untracked();
        match serde_json::from_str::<DealerSignerPackage>(&json_str) {
            Ok(pkg) => {
                add_log("OK", &format!("Parsed package for Participant {}", pkg.participant_id));
                add_log("INFO", &format!("Provisioning ID: {}", pkg.provisioning_id));
                add_log("INFO", &format!("Relays: {}", pkg.relays.join(", ")));
                set_package.set(Some(pkg));
                set_state.set(SignerState::ReadyToJoin);
            }
            Err(e) => {
                add_log("ERROR", &format!("Failed to parse JSON: {}", e));
                set_state.set(SignerState::Error(format!("Invalid JSON: {}", e)));
            }
        }
    };

    // Join session handler
    let on_join = move |_| {
        let pkg = match package.get_untracked() {
            Some(p) => p,
            None => return,
        };

        spawn_local(async move {
            let relay_list = pkg.relays.clone();
            if relay_list.is_empty() {
                add_log("ERROR", "No relays specified in signer package");
                set_state.set(SignerState::Error("No relays in package".to_string()));
                return;
            }
            for relay_url in &relay_list {
                add_log("NOSTR", &format!("Connecting to relay: {}", relay_url));
            }

            let keys = match nostr_sdk::Keys::parse(&pkg.nostr_nsec) {
                Ok(k) => k,
                Err(e) => {
                    add_log("ERROR", &format!("Invalid Nostr key: {}", e));
                    set_state.set(SignerState::Error(format!("Key error: {}", e)));
                    return;
                }
            };

            let nostr_client = Client::new(keys);
            for relay_url in &relay_list {
                if let Err(e) = nostr_client.add_relay(relay_url.as_str()).await {
                    add_log("ERROR", &format!("Failed to add relay {}: {}", relay_url, e));
                    set_state.set(SignerState::Error(format!("Relay error: {}", e)));
                    return;
                }
            }
            nostr_client.connect().await;

            // Allow TLS handshake to settle before publishing
            gloo_timers::future::TimeoutFuture::new(500).await;

            add_log("NOSTR", &format!("Connected to {} relay(s)", relay_list.len()));

            // Subscribe to coordinator events
            let round1_filter = Filter::new().kind(Kind::Custom(ROUND1_REQUEST_KIND));
            let round2_filter = Filter::new().kind(Kind::Custom(ROUND2_REQUEST_KIND));
            if let Err(e) = nostr_client.subscribe(round1_filter, None).await {
                add_log("ERROR", &format!("Failed to subscribe: {}", e));
                set_state.set(SignerState::Error(format!("Subscribe error: {}", e)));
                return;
            }
            if let Err(e) = nostr_client.subscribe(round2_filter, None).await {
                add_log("ERROR", &format!("Failed to subscribe: {}", e));
                set_state.set(SignerState::Error(format!("Subscribe error: {}", e)));
                return;
            }
            add_log("NOSTR", "Subscribed to coordinator events (Kind 23102, 23104)");

            // Send provisioning acknowledgment
            let provisioned = SignerProvisionedResponse {
                provisioning_id: pkg.provisioning_id.clone(),
                participant_id: pkg.participant_id,
            };
            let content = match serde_json::to_string(&provisioned) {
                Ok(c) => c,
                Err(e) => {
                    add_log("ERROR", &format!("Serialization error: {}", e));
                    return;
                }
            };
            match nostr_client
                .send_event_builder(
                    EventBuilder::new(Kind::Custom(SIGNER_PROVISIONED_KIND), content)
                        .tag(Tag::identifier(pkg.provisioning_id.clone())),
                )
                .await
            {
                Ok(_) => add_log("NOSTR", &format!(
                    "Published Kind {} (Signer Provisioned) for participant {}",
                    SIGNER_PROVISIONED_KIND, pkg.participant_id
                )),
                Err(e) => {
                    add_log("ERROR", &format!("Failed to publish: {}", e));
                    set_state.set(SignerState::Error(format!("Publish error: {}", e)));
                    return;
                }
            }

            set_client_store.set(Some(nostr_client.clone()));
            set_state.set(SignerState::Joined);
            add_log("OK", "Joined session. Waiting for signing request from coordinator...");

            // Start listening for round 1 requests
            listen_for_round1(
                nostr_client,
                pkg.participant_id,
                set_state,
                set_round1_req,
                set_log_entries,
            ).await;
        });
    };

    // Commit (Round 1) handler
    let on_commit = move |_| {
        let pkg = match package.get_untracked() {
            Some(p) => p,
            None => return,
        };
        let nostr_client = match client_store.get_untracked() {
            Some(c) => c,
            None => return,
        };
        let request = match round1_req.get_untracked() {
            Some(r) => r,
            None => return,
        };

        let session_id = request.session_id.clone();
        let participant_id = pkg.participant_id;
        let signing_share = pkg.key_package.signing_share().clone();

        spawn_local(async move {
            add_log("FROST", "Generating random nonces for Round 1...");

            let mut rng = frost::rand_core::OsRng;
            let (signing_nonces, commitments) =
                frost::round1::commit(&signing_share, &mut rng);

            add_log("FROST", "Nonces generated. Building commitment response...");

            let response = Round1CommitmentResponse {
                session_id: session_id.clone(),
                phase: "round1_commitment".to_string(),
                participant_id,
                commitments,
            };
            let content = match serde_json::to_string(&response) {
                Ok(c) => c,
                Err(e) => {
                    add_log("ERROR", &format!("Serialization error: {}", e));
                    return;
                }
            };

            match nostr_client
                .send_event_builder(
                    EventBuilder::new(Kind::Custom(ROUND1_RESPONSE_KIND), content)
                        .tag(Tag::identifier(session_id.clone())),
                )
                .await
            {
                Ok(_) => add_log("NOSTR", &format!(
                    "Published Kind {} (Round 1 Commitment)",
                    ROUND1_RESPONSE_KIND,
                )),
                Err(e) => {
                    add_log("ERROR", &format!("Failed to publish commitment: {}", e));
                    set_state.set(SignerState::Error(format!("Publish error: {}", e)));
                    return;
                }
            }

            set_nonces_store.set(Some(signing_nonces));
            set_session_id_store.set(Some(session_id.clone()));
            set_state.set(SignerState::Round1Committed);
            add_log("OK", "Commitment sent. Waiting for Round 2 from coordinator...");

            // Listen for round 2
            listen_for_round2(
                nostr_client,
                session_id,
                participant_id,
                set_state,
                set_round2_req,
                set_log_entries,
            ).await;
        });
    };

    // Sign (Round 2) handler
    let on_sign = move |_| {
        let pkg = match package.get_untracked() {
            Some(p) => p,
            None => return,
        };
        let nostr_client = match client_store.get_untracked() {
            Some(c) => c,
            None => return,
        };
        let signing_nonces = match nonces_store.get_untracked() {
            Some(n) => n,
            None => {
                add_log("ERROR", "No nonces stored from Round 1");
                return;
            }
        };
        let request = match round2_req.get_untracked() {
            Some(r) => r,
            None => return,
        };
        let session_id = match session_id_store.get_untracked() {
            Some(s) => s,
            None => return,
        };

        let signing_package = request.signing_package.clone();
        let key_package = pkg.key_package.clone();

        spawn_local(async move {
            add_log("FROST", "Computing signature share for Round 2...");

            let signature_share = match frost::round2::sign(
                &signing_package,
                &signing_nonces,
                &key_package,
            ) {
                Ok(share) => share,
                Err(e) => {
                    add_log("ERROR", &format!("Signing failed: {}", e));
                    set_state.set(SignerState::Error(format!("Signing error: {}", e)));
                    return;
                }
            };

            add_log("FROST", "Signature share computed. Publishing...");

            let response = Round2SignatureShareResponse {
                session_id: session_id.clone(),
                phase: "round2_signature_share".to_string(),
                participant_id: pkg.participant_id,
                signature_share,
            };
            let content = match serde_json::to_string(&response) {
                Ok(c) => c,
                Err(e) => {
                    add_log("ERROR", &format!("Serialization error: {}", e));
                    return;
                }
            };

            match nostr_client
                .send_event_builder(
                    EventBuilder::new(Kind::Custom(ROUND2_RESPONSE_KIND), content)
                        .tag(Tag::identifier(session_id.clone())),
                )
                .await
            {
                Ok(_) => add_log("NOSTR", &format!(
                    "Published Kind {} (Signature Share)",
                    ROUND2_RESPONSE_KIND,
                )),
                Err(e) => {
                    add_log("ERROR", &format!("Failed to publish share: {}", e));
                    set_state.set(SignerState::Error(format!("Publish error: {}", e)));
                    return;
                }
            }

            set_state.set(SignerState::Complete);
            add_log("OK", "Signature share sent! The coordinator will aggregate the final signature.");
        });
    };

    // Derive display values
    let state_label = move || match state.get() {
        SignerState::WaitingForPackage => ("Paste Package", "waiting"),
        SignerState::ReadyToJoin => ("Ready to Join", "waiting"),
        SignerState::Joined => ("Joined - Waiting", "connected"),
        SignerState::Round1ActionRequired => ("ACTION: Commit", "action"),
        SignerState::Round1Committed => ("Committed - Waiting", "connected"),
        SignerState::Round2ActionRequired => ("ACTION: Sign", "action"),
        SignerState::Complete => ("Complete", "done"),
        SignerState::Error(_) => ("Error", "disconnected"),
    };

    let is_waiting_for_package = move || matches!(state.get(), SignerState::WaitingForPackage);
    let is_ready_to_join = move || matches!(state.get(), SignerState::ReadyToJoin);
    let is_round1_action = move || matches!(state.get(), SignerState::Round1ActionRequired);
    let is_round2_action = move || matches!(state.get(), SignerState::Round2ActionRequired);
    let has_package = move || package.get().is_some();

    let participant_id_display = move || {
        package.get().map(|p| format!("{}", p.participant_id)).unwrap_or_default()
    };
    let provisioning_id_display = move || {
        package.get().map(|p| {
            let id = &p.provisioning_id;
            format!("{}...", &id[..12.min(id.len())])
        }).unwrap_or_default()
    };

    view! {
        <h1>"Frosty Cashu Signer"</h1>
        <h2>"Interactive FROST Threshold Signing"</h2>

        <div class="status-bar">
            <span class="status-label">"Status:"</span>
            <span class={move || format!("status-value {}", state_label().1)}>
                {move || state_label().0}
            </span>
        </div>

        <Show when=has_package>
            <div class="participant-info">
                <span class="label">"Participant: "</span>
                <span class="value">{participant_id_display}</span>
                " | "
                <span class="label">"Provisioning: "</span>
                <span class="value">{provisioning_id_display}</span>
                " | "
                <span class="label">"Relay: "</span>
                <span class="value">{move || package.get().map(|p| p.relays.join(", ")).unwrap_or_default()}</span>
            </div>
        </Show>

        <Show when=is_waiting_for_package>
            <div class="input-area">
                <textarea
                    placeholder="Paste your signer package JSON here..."
                    on:input=move |ev| {
                        let target: web_sys::HtmlTextAreaElement =
                            event_target(&ev);
                        set_package_json.set(target.value());
                    }
                />
                <button on:click=on_parse>"Parse Package"</button>
            </div>
        </Show>

        <Show when=is_ready_to_join>
            <button on:click=on_join>
                "Join Session"
            </button>
        </Show>

        <Show when=is_round1_action>
            <button class="action-required" on:click=on_commit>
                "Approve and Commit Nonces (Round 1)"
            </button>
        </Show>

        <Show when=is_round2_action>
            <button class="action-required" on:click=on_sign>
                "Finalize Signature (Round 2)"
            </button>
        </Show>

        <div class="log-container">
            <h2>"Protocol Activity"</h2>
            <LogView entries=log_entries />
        </div>
    }
}

#[component]
fn LogView(entries: ReadSignal<Vec<LogEntry>>) -> impl IntoView {
    view! {
        <div class="log" id="log-output">
            {move || {
                entries.get().into_iter().enumerate().map(|(_i, entry)| {
                    let css_class = match entry.tag.as_str() {
                        "NOSTR" => "nostr",
                        "FROST" => "frost",
                        "OK" => "ok",
                        "ERROR" => "error",
                        "ACTION" => "action",
                        _ => "info",
                    };
                    view! {
                        <div class="log-entry">
                            <span class={format!("log-tag {}", css_class)}>
                                {format!("[{}]", entry.tag)}
                            </span>
                            {entry.message}
                        </div>
                    }
                }).collect_view()
            }}
        </div>
    }
}

// ---------------------------------------------------------------------------
// Nostr event listeners
// ---------------------------------------------------------------------------

async fn listen_for_round1(
    client: Client,
    participant_id: u16,
    set_state: WriteSignal<SignerState>,
    set_round1_req: WriteSignal<Option<Round1Request>>,
    set_log_entries: WriteSignal<Vec<LogEntry>>,
) {
    let add_log = move |tag: &str, msg: &str| {
        set_log_entries.update(|entries| {
            entries.push(LogEntry {
                tag: tag.to_string(),
                message: msg.to_string(),
            });
        });
    };

    let mut notifications = client.notifications();
    loop {
        let notification = match notifications.recv().await {
            Ok(n) => n,
            Err(_) => break,
        };
        if let RelayPoolNotification::Event { event, .. } = notification {
            if event.kind != Kind::Custom(ROUND1_REQUEST_KIND) {
                continue;
            }
            let request: Round1Request = match serde_json::from_str(&event.content) {
                Ok(r) => r,
                Err(e) => {
                    add_log("ERROR", &format!("Failed to parse Round 1 request: {}", e));
                    continue;
                }
            };

            if !request.participant_ids.contains(&participant_id) {
                add_log("INFO", "Received Round 1 request but not addressed to us");
                continue;
            }

            add_log("NOSTR", &format!(
                "Received Round 1 Request (Kind {})", ROUND1_REQUEST_KIND
            ));
            add_log("INFO", &format!(
                "Session: {}...", &request.session_id[..16.min(request.session_id.len())]
            ));
            add_log("INFO", &format!(
                "Threshold: {}-of-{}", request.threshold, request.participant_ids.len()
            ));
            add_log("INFO", &format!(
                "Digest: {}...", &request.digest_hex[..16.min(request.digest_hex.len())]
            ));
            add_log("ACTION", "Press the button above to commit nonces for Round 1");

            set_round1_req.set(Some(request));
            set_state.set(SignerState::Round1ActionRequired);
            break;
        }
    }
}

async fn listen_for_round2(
    client: Client,
    session_id: String,
    participant_id: u16,
    set_state: WriteSignal<SignerState>,
    set_round2_req: WriteSignal<Option<Round2Request>>,
    set_log_entries: WriteSignal<Vec<LogEntry>>,
) {
    let add_log = move |tag: &str, msg: &str| {
        set_log_entries.update(|entries| {
            entries.push(LogEntry {
                tag: tag.to_string(),
                message: msg.to_string(),
            });
        });
    };

    let mut notifications = client.notifications();
    loop {
        let notification = match notifications.recv().await {
            Ok(n) => n,
            Err(_) => break,
        };
        if let RelayPoolNotification::Event { event, .. } = notification {
            if event.kind != Kind::Custom(ROUND2_REQUEST_KIND) {
                continue;
            }
            let request: Round2Request = match serde_json::from_str(&event.content) {
                Ok(r) => r,
                Err(e) => {
                    add_log("ERROR", &format!("Failed to parse Round 2 request: {}", e));
                    continue;
                }
            };

            if request.session_id != session_id {
                continue;
            }

            if !request.selected_participant_ids.contains(&participant_id) {
                add_log("INFO", "Not selected for this signing quorum");
                set_state.set(SignerState::Complete);
                break;
            }

            add_log("NOSTR", &format!(
                "Received Round 2 Request (Kind {})", ROUND2_REQUEST_KIND
            ));
            add_log("INFO", &format!(
                "Selected signers: {:?}", request.selected_participant_ids
            ));
            add_log("ACTION", "Press the button above to finalize your signature share");

            set_round2_req.set(Some(request));
            set_state.set(SignerState::Round2ActionRequired);
            break;
        }
    }
}
