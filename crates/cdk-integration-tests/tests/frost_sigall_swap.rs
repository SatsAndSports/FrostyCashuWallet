use std::sync::Arc;

use bitcoin::hashes::{sha256, Hash};

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
use p2pk_sigall_swap_support::{
    frost_signature_hex, prepare_p2pk_sigall_swap, swap_request_with_signature_hex, FrostDemoGroup,
    DEFAULT_LOCK_AMOUNT_SATS, DEMO_SECRET_HEX,
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
    let frost_group = FrostDemoGroup::from_existing_secret(&source_secret)
        .expect("split known secret into FROST shares");
    let prepared = prepare_p2pk_sigall_swap(
        &wallet,
        Amount::from(DEFAULT_LOCK_AMOUNT_SATS),
        frost_group.group_public_key,
    )
    .await
    .expect("prepare SIG_ALL swap");

    assert_eq!(frost_group.threshold, 2);
    assert_eq!(frost_group.max_signers, 3);
    assert_eq!(frost_group.selected_signer_count(), 2);
    assert_eq!(
        source_secret.public_key().x_only_public_key(),
        frost_group.group_public_key.x_only_public_key()
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

    let frost_signed = prepared
        .sign_with_frost(&frost_group)
        .expect("aggregate FROST signature");

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
    let frost_group = FrostDemoGroup::from_existing_secret(&source_secret)
        .expect("split known secret into FROST shares");
    let prepared = prepare_p2pk_sigall_swap(
        &wallet,
        Amount::from(DEFAULT_LOCK_AMOUNT_SATS),
        frost_group.group_public_key,
    )
    .await
    .expect("prepare SIG_ALL swap");

    let wrong_signature = frost_signature_hex(prepared.sig_all_message().as_bytes(), &frost_group)
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

    let correct_signed = prepared
        .sign_with_frost(&frost_group)
        .expect("FROST signs the SHA256 digest bytes");
    correct_signed
        .request
        .verify_spending_conditions()
        .expect("digest-signed request verifies locally");
}
