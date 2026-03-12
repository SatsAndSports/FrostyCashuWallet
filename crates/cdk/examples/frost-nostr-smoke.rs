#![allow(missing_docs)]

use std::env;
use std::time::Duration;

use nostr_sdk::{Client, EventBuilder, Filter, Keys, Kind, RelayPoolNotification, Tag, ToBech32};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout};

const REQUEST_KIND: u16 = 23100;
const RESPONSE_KIND: u16 = 23101;
const DEFAULT_RELAY_URL: &str = "ws://127.0.0.1:7777";
const DEFAULT_TIMEOUT_SECS: u64 = 10;

type DemoResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DealerSignerPackage {
    participant_id: u16,
    nostr_nsec: String,
    relay_url: String,
    note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CoordinatorPing {
    session_id: String,
    phase: String,
    digest_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignerPong {
    session_id: String,
    phase: String,
    participant_id: u16,
    seen_digest_hex: String,
}

fn env_u64(name: &str, default: u64) -> DemoResult<u64> {
    match env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(_) => Ok(default),
    }
}

fn keys_from_env_or_generate(name: &str) -> DemoResult<Keys> {
    match env::var(name) {
        Ok(nsec) => Ok(Keys::parse(&nsec)?),
        Err(_) => Ok(Keys::generate()),
    }
}

#[tokio::main]
async fn main() -> DemoResult<()> {
    let relay_url = env::var("NOSTR_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY_URL.to_string());
    let timeout_secs = env_u64("NOSTR_SMOKE_TIMEOUT_SECS", DEFAULT_TIMEOUT_SECS)?;
    let coordinator_keys = keys_from_env_or_generate("NOSTR_COORDINATOR_NSEC")?;
    let signer_keys = keys_from_env_or_generate("NOSTR_SIGNER_NSEC")?;
    let signer_package = DealerSignerPackage {
        participant_id: 1,
        nostr_nsec: signer_keys.secret_key().to_bech32()?,
        relay_url: relay_url.clone(),
        note: "Smoke step only: this package carries only the Nostr key, not the FROST share"
            .to_string(),
    };
    let session_id = format!("frost-smoke-{}", uuid::Uuid::new_v4());
    let digest_hex = format!("{}", uuid::Uuid::new_v4().simple());

    println!("FROST Nostr smoke test");
    println!("Relay: {}", relay_url);
    println!("Session: {}", session_id);
    println!(
        "Coordinator npub: {}",
        coordinator_keys.public_key().to_bech32()?
    );
    println!("Signer npub: {}", signer_keys.public_key().to_bech32()?);
    println!(
        "Dealer signer package:\n{}",
        serde_json::to_string_pretty(&signer_package)?
    );

    let (ready_tx, ready_rx) = oneshot::channel();
    let signer_relay = relay_url.clone();
    let signer_session = session_id.clone();
    let signer_digest = digest_hex.clone();
    let coordinator_pubkey = coordinator_keys.public_key();
    let signer_pubkey = signer_keys.public_key();

    let signer_handle = tokio::spawn(async move {
        run_signer(
            signer_keys,
            signer_relay,
            signer_session,
            signer_digest,
            coordinator_pubkey,
            signer_package.participant_id,
            ready_tx,
        )
        .await
    });

    ready_rx.await?;

    let coordinator_client = Client::new(coordinator_keys.clone());
    coordinator_client.add_relay(relay_url.as_str()).await?;
    coordinator_client.connect().await;

    let response_filter = Filter::new()
        .kind(Kind::Custom(RESPONSE_KIND))
        .author(signer_pubkey)
        .identifier(session_id.clone());
    coordinator_client.subscribe(response_filter, None).await?;

    sleep(Duration::from_millis(250)).await;

    let ping = CoordinatorPing {
        session_id: session_id.clone(),
        phase: "ping".to_string(),
        digest_hex: digest_hex.clone(),
    };
    let request_builder =
        EventBuilder::new(Kind::Custom(REQUEST_KIND), serde_json::to_string(&ping)?)
            .tag(Tag::identifier(session_id.clone()));

    let output = coordinator_client
        .send_event_builder(request_builder)
        .await?;
    println!("Published request event: {}", output.id().to_bech32()?);

    let response = wait_for_pong(&coordinator_client, &session_id, timeout_secs).await?;
    println!(
        "Received signer response:\n{}",
        serde_json::to_string_pretty(&response)?
    );

    if response.session_id != session_id {
        return Err("Signer replied with the wrong session id".into());
    }
    if response.phase != "pong" {
        return Err("Signer replied with the wrong phase".into());
    }
    if response.seen_digest_hex != digest_hex {
        return Err("Signer echoed the wrong digest".into());
    }

    println!("Nostr smoke test succeeded");

    coordinator_client.disconnect().await;

    let signer_result = signer_handle.await??;
    if signer_result.session_id != session_id {
        return Err("Signer task observed the wrong session id".into());
    }

    Ok(())
}

async fn run_signer(
    signer_keys: Keys,
    relay_url: String,
    session_id: String,
    expected_digest_hex: String,
    coordinator_pubkey: nostr_sdk::PublicKey,
    participant_id: u16,
    ready_tx: oneshot::Sender<()>,
) -> DemoResult<SignerPong> {
    let signer_client = Client::new(signer_keys);
    signer_client.add_relay(relay_url.as_str()).await?;
    signer_client.connect().await;

    let request_filter = Filter::new()
        .kind(Kind::Custom(REQUEST_KIND))
        .author(coordinator_pubkey)
        .identifier(session_id.clone());
    signer_client.subscribe(request_filter, None).await?;

    let _ = ready_tx.send(());

    let ping = wait_for_ping(&signer_client, &session_id).await?;
    if ping.digest_hex != expected_digest_hex {
        return Err("Coordinator published an unexpected digest".into());
    }

    let pong = SignerPong {
        session_id: ping.session_id,
        phase: "pong".to_string(),
        participant_id,
        seen_digest_hex: ping.digest_hex,
    };
    let response_builder =
        EventBuilder::new(Kind::Custom(RESPONSE_KIND), serde_json::to_string(&pong)?)
            .tag(Tag::identifier(session_id));

    let output = signer_client.send_event_builder(response_builder).await?;
    println!(
        "Signer published response event: {}",
        output.id().to_bech32()?
    );
    signer_client.disconnect().await;

    Ok(pong)
}

async fn wait_for_ping(client: &Client, session_id: &str) -> DemoResult<CoordinatorPing> {
    let mut notifications = client.notifications();

    loop {
        let notification = notifications.recv().await?;
        if let RelayPoolNotification::Event { event, .. } = notification {
            if event.kind != Kind::Custom(REQUEST_KIND) {
                continue;
            }

            let ping: CoordinatorPing = serde_json::from_str(&event.content)?;
            if ping.session_id == session_id {
                return Ok(ping);
            }
        }
    }
}

async fn wait_for_pong(
    client: &Client,
    session_id: &str,
    timeout_secs: u64,
) -> DemoResult<SignerPong> {
    let mut notifications = client.notifications();

    let pong = timeout(Duration::from_secs(timeout_secs), async move {
        loop {
            let notification = notifications.recv().await?;
            if let RelayPoolNotification::Event { event, .. } = notification {
                if event.kind != Kind::Custom(RESPONSE_KIND) {
                    continue;
                }

                let pong: SignerPong = serde_json::from_str(&event.content)?;
                if pong.session_id == session_id {
                    return Ok::<SignerPong, Box<dyn std::error::Error + Send + Sync>>(pong);
                }
            }
        }
    })
    .await??;

    Ok(pong)
}
