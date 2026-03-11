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
    prepare_p2pk_sigall_swap, CHEAT_SECRET_HEX, DEFAULT_LOCK_AMOUNT_SATS,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_cheat_signed_sigall_swap_succeeds() {
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

    let signer = SecretKey::from_hex(CHEAT_SECRET_HEX).expect("Valid fixed signer secret");
    let prepared = prepare_p2pk_sigall_swap(
        &wallet,
        Amount::from(DEFAULT_LOCK_AMOUNT_SATS),
        signer.public_key(),
    )
    .await
    .expect("prepare SIG_ALL swap");

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

    let manual_signed = prepared
        .manually_sign(&signer)
        .expect("manual cheat signature");
    let built_in_signature = prepared
        .built_in_sig_all_signature(&signer)
        .expect("built-in sigall signature");

    assert_eq!(manual_signed.signature_hex.len(), 128);
    assert_eq!(built_in_signature.len(), 128);
    assert_eq!(
        manual_signed.digest_hex,
        sha256::Hash::hash(manual_signed.message.as_bytes()).to_string()
    );
    manual_signed
        .request
        .verify_spending_conditions()
        .expect("signed request verifies locally");

    let manual_message = manual_signed.message.clone();
    let manual_digest = manual_signed.digest_hex.clone();
    let manual_signature = manual_signed.signature_hex.clone();

    let connector: Arc<dyn MintConnector + Send + Sync> = Arc::new(DirectMintConnection::new(mint));
    let completed = prepared
        .execute_signed_swap(connector, manual_signed)
        .await
        .expect("signed swap succeeds");

    assert_eq!(completed.signed_swap.message, manual_message);
    assert_eq!(completed.signed_swap.digest_hex, manual_digest);
    assert_eq!(completed.signed_swap.signature_hex, manual_signature);

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
