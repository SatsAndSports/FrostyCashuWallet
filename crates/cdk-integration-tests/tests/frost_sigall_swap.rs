use std::sync::Arc;

use bitcoin::hashes::{sha256, Hash};

mod frost_nostr_support {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../cdk/examples/support/frost_nostr.rs"
    ));
}

mod p2pk_sigall_swap_support {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../cdk/examples/support/p2pk_sigall_swap.rs"
    ));
}

use cdk::nuts::nut00::ProofsMethods;
use cdk::nuts::{SecretKey, SpendingConditionVerification};
use cdk::wallet::MintConnector;
use cdk::Amount;
use cdk_integration_tests::init_pure_tests::{
    create_and_start_test_mint, create_test_wallet_for_mint, fund_wallet, setup_tracing,
    DirectMintConnection,
};
use frost_nostr_support::{dealer_setup, DEFAULT_MAX_SIGNERS, DEFAULT_THRESHOLD, DEMO_SECRET_HEX};
use p2pk_sigall_swap_support::{
    prepare_p2pk_sigall_swap, swap_request_with_signature_hex, DEFAULT_LOCK_AMOUNT_SATS,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_frost_signed_sigall_swap_succeeds() {
    setup_tracing();

    let mint = create_and_start_test_mint()
        .await
        .expect("Failed to create test mint");
    let wallet = create_test_wallet_for_mint(mint.clone())
        .await
        .expect("Failed to create test wallet");
    fund_wallet(wallet.clone(), 64, None)
        .await
        .expect("Failed to fund wallet");

    let source_secret = SecretKey::from_hex(DEMO_SECRET_HEX).expect("Valid fixed signer secret");
    let dealer = dealer_setup(
        &source_secret,
        "ws://unused-in-local-test",
        DEFAULT_MAX_SIGNERS,
        DEFAULT_THRESHOLD,
    )
    .expect("dealer setup");

    let prepared = prepare_p2pk_sigall_swap(
        &wallet,
        Amount::from(DEFAULT_LOCK_AMOUNT_SATS),
        dealer.group_public_key,
    )
    .await
    .expect("prepare SIG_ALL swap");

    assert_eq!(dealer.threshold, 2);
    assert_eq!(dealer.max_signers, 3);
    assert_eq!(dealer.signer_packages.len(), 3);
    assert_eq!(
        source_secret.public_key().x_only_public_key(),
        dealer.group_public_key.x_only_public_key()
    );
    assert_eq!(prepared.lock_amount, Amount::from(DEFAULT_LOCK_AMOUNT_SATS));
    assert_eq!(
        prepared
            .locked_token
            .value()
            .expect("locked token has value"),
        prepared.lock_amount
    );
    assert_eq!(
        prepared.locked_token_string,
        prepared.locked_token.to_string()
    );
    assert_eq!(
        prepared
            .locked_proofs
            .total_amount()
            .expect("locked proofs total"),
        prepared.input_amount
    );
    assert_eq!(
        prepared
            .output_amount
            .checked_add(prepared.input_fee)
            .expect("output plus fee fits"),
        prepared.input_amount
    );
    assert_eq!(prepared.lock_swap_fee, Amount::ZERO);

    let err = prepared
        .unsigned_swap_request
        .verify_spending_conditions()
        .expect_err("unsigned SIG_ALL request should fail");
    assert!(matches!(
        err,
        cdk::nuts::nut11::Error::SignaturesNotProvided
    ));

    // Use a local in-process FROST sign to test the Cashu swap path
    // without needing a relay. This exercises the same crypto as the
    // Nostr-backed path but skips the transport layer.
    let payload = prepared.signing_payload();
    let signature_hex =
        local_frost_sign(&dealer, payload.message.as_bytes()).expect("local FROST sign");
    let frost_signed = prepared
        .build_signed_swap(&payload, signature_hex)
        .expect("build signed swap");

    assert_eq!(frost_signed.signature_hex.len(), 128);
    assert_eq!(
        frost_signed.digest_hex,
        sha256::Hash::hash(frost_signed.message.as_bytes()).to_string()
    );
    frost_signed
        .request
        .verify_spending_conditions()
        .expect("signed request verifies locally");

    let frost_message = frost_signed.message.clone();
    let frost_digest = frost_signed.digest_hex.clone();
    let frost_signature = frost_signed.signature_hex.clone();

    let connector: Arc<dyn MintConnector + Send + Sync> = Arc::new(DirectMintConnection::new(mint));
    let completed = prepared
        .execute_signed_swap(connector, frost_signed)
        .await
        .expect("signed swap succeeds");

    assert_eq!(completed.signed_swap.message, frost_message);
    assert_eq!(completed.signed_swap.digest_hex, frost_digest);
    assert_eq!(completed.signed_swap.signature_hex, frost_signature);
    assert_eq!(
        completed
            .unlocked_token
            .value()
            .expect("unlocked token has value"),
        prepared.output_amount
    );
    assert_eq!(
        completed
            .unlocked_proofs
            .total_amount()
            .expect("unlocked proofs have amount"),
        prepared.output_amount
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_frost_signature_must_sign_sigall_digest() {
    setup_tracing();

    let mint = create_and_start_test_mint()
        .await
        .expect("Failed to create test mint");
    let wallet = create_test_wallet_for_mint(mint)
        .await
        .expect("Failed to create test wallet");
    fund_wallet(wallet.clone(), 64, None)
        .await
        .expect("Failed to fund wallet");

    let source_secret = SecretKey::from_hex(DEMO_SECRET_HEX).expect("Valid fixed signer secret");
    let dealer = dealer_setup(
        &source_secret,
        "ws://unused-in-local-test",
        DEFAULT_MAX_SIGNERS,
        DEFAULT_THRESHOLD,
    )
    .expect("dealer setup");

    let prepared = prepare_p2pk_sigall_swap(
        &wallet,
        Amount::from(DEFAULT_LOCK_AMOUNT_SATS),
        dealer.group_public_key,
    )
    .await
    .expect("prepare SIG_ALL swap");

    // Sign the raw message bytes directly (wrong: skips SHA-256 prehash)
    let wrong_signature =
        local_frost_sign_raw_bytes(&dealer, prepared.sig_all_message().as_bytes())
            .expect("FROST signs raw message bytes");
    let wrong_request =
        swap_request_with_signature_hex(&prepared.unsigned_swap_request, wrong_signature)
            .expect("attach wrong signature to request");
    let err = wrong_request
        .verify_spending_conditions()
        .expect_err("raw message signature should fail CDK verification");

    assert!(matches!(
        err,
        cdk::nuts::nut11::Error::SpendConditionsNotMet
    ));

    // Sign sha256(message) (correct: matches CDK's prehash convention)
    let payload = prepared.signing_payload();
    let correct_signature =
        local_frost_sign(&dealer, payload.message.as_bytes()).expect("FROST signs correctly");
    let correct_signed = prepared
        .build_signed_swap(&payload, correct_signature)
        .expect("build correctly signed swap");
    correct_signed
        .request
        .verify_spending_conditions()
        .expect("digest-signed request verifies locally");
}

/// Local in-process FROST signing for tests (no Nostr relay needed).
/// Signs `sha256(msg)` — matching CDK's prehash-then-Schnorr convention.
fn local_frost_sign(
    dealer: &frost_nostr_support::DealerSetup,
    msg: &[u8],
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
    use frost_secp256k1_tr as frost;
    use std::collections::BTreeMap;

    let digest = sha256::Hash::hash(msg);
    let digest_bytes = digest.as_byte_array();

    let mut rng = frost::rand_core::OsRng;
    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();

    // Use the first `threshold` signers
    let signer_packages: Vec<_> = dealer
        .signer_packages
        .iter()
        .take(dealer.threshold as usize)
        .collect();

    for package in &signer_packages {
        let identifier = frost::Identifier::try_from(package.participant_id)?;
        let (nonces, commitments) =
            frost::round1::commit(package.key_package.signing_share(), &mut rng);
        nonces_map.insert(identifier, nonces);
        commitments_map.insert(identifier, commitments);
    }

    let signing_package = frost::SigningPackage::new(commitments_map, digest_bytes);
    let mut signature_shares = BTreeMap::new();

    for package in &signer_packages {
        let identifier = frost::Identifier::try_from(package.participant_id)?;
        let nonces = nonces_map.get(&identifier).ok_or("missing nonces")?;
        let share = frost::round2::sign(&signing_package, nonces, &package.key_package)?;
        signature_shares.insert(identifier, share);
    }

    let group_signature = frost::aggregate(
        &signing_package,
        &signature_shares,
        &dealer.public_key_package,
    )?;
    dealer
        .public_key_package
        .verifying_key()
        .verify(digest_bytes, &group_signature)?;

    let sig = SchnorrSignature::from_slice(group_signature.serialize()?.as_slice())?;
    Ok(sig.to_string())
}

/// Signs the given bytes directly without SHA-256 prehash.
/// Used only for the negative test to prove that skipping the prehash fails.
fn local_frost_sign_raw_bytes(
    dealer: &frost_nostr_support::DealerSetup,
    raw_bytes: &[u8],
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
    use frost_secp256k1_tr as frost;
    use std::collections::BTreeMap;

    let mut rng = frost::rand_core::OsRng;
    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();

    let signer_packages: Vec<_> = dealer
        .signer_packages
        .iter()
        .take(dealer.threshold as usize)
        .collect();

    for package in &signer_packages {
        let identifier = frost::Identifier::try_from(package.participant_id)?;
        let (nonces, commitments) =
            frost::round1::commit(package.key_package.signing_share(), &mut rng);
        nonces_map.insert(identifier, nonces);
        commitments_map.insert(identifier, commitments);
    }

    let signing_package = frost::SigningPackage::new(commitments_map, raw_bytes);
    let mut signature_shares = BTreeMap::new();

    for package in &signer_packages {
        let identifier = frost::Identifier::try_from(package.participant_id)?;
        let nonces = nonces_map.get(&identifier).ok_or("missing nonces")?;
        let share = frost::round2::sign(&signing_package, nonces, &package.key_package)?;
        signature_shares.insert(identifier, share);
    }

    let group_signature = frost::aggregate(
        &signing_package,
        &signature_shares,
        &dealer.public_key_package,
    )?;

    let sig = SchnorrSignature::from_slice(group_signature.serialize()?.as_slice())?;
    Ok(sig.to_string())
}
