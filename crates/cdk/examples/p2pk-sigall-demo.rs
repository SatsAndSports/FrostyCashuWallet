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
    Conditions, CurrencyUnit, PaymentMethod, SecretKey as CashuSecretKey, SigFlag,
    SpendingConditionVerification, SpendingConditions,
};
use cdk::wallet::{HttpClient, MintConnector, WalletBuilder};
use cdk::Amount;
use cdk_sqlite::wallet::memory;
use frost_nostr_support::{
    dealer_setup, provision_signers, sign_message_via_nostr, wait_for_external_signers,
    NostrFrostCoordinatorConfig, DEFAULT_MAX_SIGNERS, DEFAULT_NOSTR_RELAYS, DEFAULT_THRESHOLD,
    DEMO_SECRET_HEX,
};
use lightning_invoice::Bolt11Invoice;
use nostr_sdk::{Keys, SecretKey as NostrSecretKey, ToBech32};
use p2pk_sigall_swap_support::{
    get_melt_quote, prepare_sigall_melt, prepare_sigall_spend, SigAllSigningPayload,
    DEFAULT_LOCK_AMOUNT_SATS,
};
use rand::random;

fn env_u64(name: &str, default: u64) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    match env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(_) => Ok(default),
    }
}

/// Parse CLI arguments. Returns (interactive, bolt11_invoice).
fn parse_cli_args() -> (bool, Option<String>) {
    let args: Vec<String> = env::args().collect();
    let interactive = args.iter().any(|a| a == "--interactive");
    let bolt11 = args.iter().find(|a| {
        let lower = a.to_lowercase();
        lower.starts_with("lnbc") || lower.starts_with("lntbs") || lower.starts_with("lntb")
    });
    (interactive, bolt11.cloned())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mint_url: MintUrl = env::var("CDK_MINT_URL")
        .unwrap_or_else(|_| "https://mint.minibits.cash/Bitcoin".to_string())
        .parse()?;
    let frost_max_signers = env_u64("CDK_FROST_MAX_SIGNERS", DEFAULT_MAX_SIGNERS as u64)? as u16;
    let frost_threshold = env_u64("CDK_FROST_THRESHOLD", DEFAULT_THRESHOLD as u64)? as u16;
    let relays: Vec<String> = match env::var("NOSTR_RELAYS") {
        Ok(value) => value.split(',').map(|s| s.trim().to_string()).collect(),
        Err(_) => DEFAULT_NOSTR_RELAYS.iter().map(|s| s.to_string()).collect(),
    };

    let default_nsec = NostrSecretKey::from_hex(DEMO_SECRET_HEX)?.to_bech32()?;
    let seed_nsec = env::var("NOSTR_NSEC").unwrap_or(default_nsec);
    let nostr_keys = Keys::parse(&seed_nsec)?;
    let signer = CashuSecretKey::from_slice(&nostr_keys.secret_key().to_secret_bytes())?;

    let dealer = dealer_setup(&signer, &relays, frost_max_signers, frost_threshold)?;

    let coordinator_keys = match env::var("NOSTR_COORDINATOR_NSEC") {
        Ok(nsec) => Keys::parse(&nsec)?,
        Err(_) => Keys::generate(),
    };
    let config = NostrFrostCoordinatorConfig {
        relays: relays.clone(),
        coordinator_keys: coordinator_keys.clone(),
        session_id: env::var("CDK_FROST_SESSION_ID").ok(),
        session_prefix: "cashu-demo".to_string(),
    };

    let (interactive, bolt11_invoice) = parse_cli_args();

    let provisioned = if interactive {
        println!("\n--- INTERACTIVE MODE ---");
        println!(
            "Distribute the following {} signer packages to your participants.\n",
            dealer.signer_packages.len()
        );
        for (i, package) in dealer.signer_packages.iter().enumerate() {
            println!(
                "=== Participant {} (of {}) ===",
                i + 1,
                dealer.max_signers
            );
            println!("{}", serde_json::to_string(package)?);
            println!();
        }
        println!(
            "Waiting for {} signers to join via the web app...",
            dealer.max_signers
        );
        wait_for_external_signers(&dealer, &config).await?
    } else {
        println!("Provisioning signers...");
        provision_signers(&dealer, &config).await?
    };
    println!(
        "All {} signers acknowledged their packages ({})",
        dealer.max_signers, dealer.provisioning_id
    );

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

    let spending_conditions = SpendingConditions::new_p2pk(
        dealer.group_public_key,
        Some(Conditions::new(
            None,
            None,
            None,
            None,
            Some(SigFlag::SigAll),
            None,
        )?),
    );

    println!("\nMint URL: {}", mint_url);
    println!("FROST transport: Nostr");
    println!("Seed signer pubkey: {}", signer.public_key());
    println!("FROST group pubkey: {}", dealer.group_public_key);
    println!(
        "FROST quorum: {}-of-{}",
        dealer.threshold, dealer.max_signers
    );
    println!("Participants: {}", dealer.signer_packages.len());

    if let Some(ref invoice_str) = bolt11_invoice {
        // ---------------------------------------------------------------
        // MELT PATH: pay a Lightning invoice from FROST-locked proofs
        // ---------------------------------------------------------------
        println!("\n--- MELT MODE ---");

        let invoice: Bolt11Invoice = invoice_str.parse()?;
        let invoice_msats = invoice
            .amount_milli_satoshis()
            .ok_or("invoice has no amount")?;
        let invoice_sats = (invoice_msats + 999) / 1000; // round up
        println!("Invoice amount: {} sats ({} msats)", invoice_sats, invoice_msats);

        // Get a melt quote to learn the fee reserve
        let melt_quote = get_melt_quote(&wallet, invoice_str).await?;
        let fund_amount_sats: u64 = u64::from(melt_quote.amount)
            + u64::from(melt_quote.fee_reserve);
        println!(
            "Melt quote: amount={}, fee_reserve={}, total={}",
            melt_quote.amount, melt_quote.fee_reserve, fund_amount_sats
        );
        println!("Melt quote ID: {}", melt_quote.id);

        // Mint directly to FROST-locked proofs
        let quote = wallet
            .mint_quote(
                PaymentMethod::BOLT11,
                Some(Amount::from(fund_amount_sats)),
                None,
                None,
            )
            .await?;

        println!(
            "\nPay this invoice to fund the melt demo ({fund_amount_sats} sats):"
        );
        println!("{}\n", quote.request);

        let minted_proofs = wallet
            .wait_and_mint_quote(
                quote,
                Default::default(),
                Some(spending_conditions),
                Duration::from_secs(3600),
            )
            .await?;

        println!(
            "Minted {} sats directly to FROST-locked proofs",
            minted_proofs.total_amount()?
        );

        // Prepare the melt request
        let prepared = prepare_sigall_melt(melt_quote, minted_proofs)?;

        println!("Melt input amount: {}", prepared.input_amount);
        println!("Melt quote ID: {}", prepared.quote.id);

        match prepared
            .unsigned_melt_request
            .verify_spending_conditions()
        {
            Ok(()) => println!("Unsigned melt request unexpectedly verified"),
            Err(err) => println!("Unsigned melt request fails as expected: {}", err),
        }

        // FROST sign
        let payload = prepared.signing_payload();
        print_signing_info(&payload, &coordinator_keys, &relays)?;

        let result =
            sign_message_via_nostr(&dealer, &payload.message, &config).await?;
        let signed =
            prepared.build_signed_melt(&payload, result.signature_hex)?;

        println!("Nostr session: {}", result.session_id);
        println!(
            "Nostr selected signers: {:?}",
            result.selected_participant_ids
        );
        println!("\nSIG_ALL message:\n{}", signed.message);
        println!("SHA256 prehash: {}", signed.digest_hex);
        println!("FROST signature: {}", signed.signature_hex);

        // Submit the signed melt
        let completed =
            prepared.execute_signed_melt(connector, signed).await?;

        println!("\n--- MELT RESULT ---");
        println!("State: {:?}", completed.response.state);
        println!(
            "Payment preimage: {}",
            completed
                .response
                .payment_preimage
                .as_deref()
                .unwrap_or("(none)")
        );
        println!(
            "Submitted signature: {}",
            completed.signed_melt.signature_hex
        );
    } else {
        // ---------------------------------------------------------------
        // SWAP PATH: swap FROST-locked proofs to unlocked proofs
        // ---------------------------------------------------------------
        println!("\n--- SWAP MODE ---");
        println!("(Pass a bolt11 invoice as the first argument to use melt mode)");

        let lock_amount_sats =
            env_u64("CDK_LOCK_AMOUNT", DEFAULT_LOCK_AMOUNT_SATS)?;
        let fund_amount_sats =
            env_u64("CDK_FUND_AMOUNT", lock_amount_sats.saturating_add(4))?;

        let quote = wallet
            .mint_quote(
                PaymentMethod::BOLT11,
                Some(Amount::from(fund_amount_sats)),
                None,
                None,
            )
            .await?;

        println!(
            "\nPay this invoice to fund the swap demo ({fund_amount_sats} sats):"
        );
        println!("{}\n", quote.request);

        let minted_proofs = wallet
            .wait_and_mint_quote(
                quote,
                Default::default(),
                Some(spending_conditions),
                Duration::from_secs(3600),
            )
            .await?;

        println!(
            "Minted {} sats directly to FROST-locked proofs",
            minted_proofs.total_amount()?
        );

        let prepared =
            prepare_sigall_spend(&wallet, minted_proofs).await?;

        println!("\nLocked token amount: {}", prepared.lock_amount);
        println!(
            "Locked token value: {}",
            prepared.locked_token.value()?
        );
        println!("Locked proof count: {}", prepared.locked_proofs.len());
        println!("Locked proofs total: {}", prepared.input_amount);
        println!("Spend-side input fee: {}", prepared.input_fee);
        println!("Unlocked output amount: {}", prepared.output_amount);
        println!("Locked token:\n{}", prepared.locked_token_string);

        match prepared
            .unsigned_swap_request
            .verify_spending_conditions()
        {
            Ok(()) => println!("Unsigned request unexpectedly verified"),
            Err(err) => {
                println!("Unsigned request fails as expected: {}", err)
            }
        }

        let payload = prepared.signing_payload();
        print_signing_info(&payload, &coordinator_keys, &relays)?;

        let result =
            sign_message_via_nostr(&dealer, &payload.message, &config).await?;
        let signed =
            prepared.build_signed_swap(&payload, result.signature_hex)?;

        println!("Nostr session: {}", result.session_id);
        println!(
            "Nostr selected signers: {:?}",
            result.selected_participant_ids
        );
        println!("\nSIG_ALL message:\n{}", signed.message);
        println!("SHA256 prehash: {}", signed.digest_hex);
        println!("FROST signature: {}", signed.signature_hex);

        let completed =
            prepared.execute_signed_swap(connector, signed).await?;

        println!("\n--- SWAP RESULT ---");
        println!(
            "Submitted signature: {}",
            completed.signed_swap.signature_hex
        );
        println!(
            "Unlocked proofs total: {}",
            completed.unlocked_proofs.total_amount()?
        );
        println!(
            "Unlocked token amount: {}",
            completed.unlocked_token.value()?
        );
        println!("Unlocked token:\n{}", completed.unlocked_token);
    }

    provisioned.shutdown().await?;

    Ok(())
}

fn print_signing_info(
    payload: &SigAllSigningPayload,
    coordinator_keys: &Keys,
    relays: &[String],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!(
        "\nNostr coordinator npub: {}",
        coordinator_keys.public_key().to_bech32()?
    );
    println!("Nostr relays: {}", relays.join(", "));
    println!("Signing payload digest: {}", payload.digest_hex);
    Ok(())
}
