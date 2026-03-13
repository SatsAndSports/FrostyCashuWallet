use std::io;
use std::sync::Arc;

use bitcoin::hashes::{sha256, Hash};
use cdk::amount::SplitTarget;
use cdk::dhke::construct_proofs;
use cdk::mint_url::MintUrl;
use cdk::nuts::nut00::ProofsMethods;
use cdk::nuts::nut05::MeltRequest;
use cdk::nuts::nut23::MeltQuoteBolt11Response;
use cdk::nuts::{
    Conditions, CurrencyUnit, Keys, P2PKWitness, PaymentMethod, PreMintSecrets, Proofs, PublicKey,
    SigFlag, SpendingConditionVerification, SpendingConditions, SwapRequest, Token, Witness,
};
use cdk::wallet::{MeltQuote, MintConnector, SendOptions, Wallet};
use cdk::Amount;

pub type DemoResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub const DEFAULT_LOCK_AMOUNT_SATS: u64 = 10;

#[derive(Debug, Clone)]
pub struct PreparedSigAllSwap {
    pub lock_amount: Amount,
    pub lock_swap_fee: Amount,
    pub locked_token: Token,
    pub locked_token_string: String,
    pub locked_proofs: Proofs,
    pub input_amount: Amount,
    pub input_fee: Amount,
    pub output_amount: Amount,
    pub unsigned_swap_request: SwapRequest,
    output_premint: PreMintSecrets,
    output_keys: Keys,
    mint_url: MintUrl,
    unit: CurrencyUnit,
}

#[derive(Debug, Clone)]
pub struct SignedSigAllSwap {
    pub request: SwapRequest,
    pub message: String,
    pub digest_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone)]
pub struct CompletedSigAllSwap {
    pub signed_swap: SignedSigAllSwap,
    pub unlocked_proofs: Proofs,
    pub unlocked_token: Token,
}

#[derive(Debug, Clone)]
pub struct SigAllSigningPayload {
    pub message: String,
    pub digest_hex: String,
}

pub async fn prepare_p2pk_sigall_swap(
    wallet: &Wallet,
    lock_amount: Amount,
    signing_pubkey: PublicKey,
) -> DemoResult<PreparedSigAllSwap> {
    let spending_conditions = SpendingConditions::new_p2pk(
        signing_pubkey,
        Some(Conditions::new(
            None,
            None,
            None,
            None,
            Some(SigFlag::SigAll),
            None,
        )?),
    );

    let prepared_send = wallet
        .prepare_send(
            lock_amount,
            SendOptions {
                conditions: Some(spending_conditions),
                include_fee: true,
                ..Default::default()
            },
        )
        .await?;
    let lock_swap_fee = prepared_send.swap_fee();
    let locked_token = prepared_send.confirm(None).await?;
    let locked_token_string = locked_token.to_string();

    let mint_url = locked_token.mint_url()?;
    let unit = locked_token
        .unit()
        .ok_or_else(|| io::Error::other("missing token unit"))?;

    let mint_keysets = wallet.get_mint_keysets().await?;
    let locked_proofs = locked_token.proofs(&mint_keysets)?;
    let input_amount = locked_proofs.total_amount()?;
    let input_fee = wallet.get_proofs_fee(&locked_proofs).await?.total;
    let output_amount = input_amount
        .checked_sub(input_fee)
        .ok_or_else(|| io::Error::other("SIG_ALL demo amount underflow"))?;

    if output_amount == Amount::ZERO {
        return Err(io::Error::other("SIG_ALL demo output amount is zero").into());
    }

    let active_keyset = wallet.get_active_keyset().await?;
    let fee_and_amounts = wallet
        .get_keyset_fees_and_amounts_by_id(active_keyset.id)
        .await?;
    let output_keys = wallet.load_keyset_keys(active_keyset.id).await?;
    let output_premint = PreMintSecrets::random(
        active_keyset.id,
        output_amount,
        &SplitTarget::default(),
        &fee_and_amounts,
    )?;
    let unsigned_swap_request =
        SwapRequest::new(locked_proofs.clone(), output_premint.blinded_messages());

    Ok(PreparedSigAllSwap {
        lock_amount,
        lock_swap_fee,
        locked_token,
        locked_token_string,
        locked_proofs,
        input_amount,
        input_fee,
        output_amount,
        unsigned_swap_request,
        output_premint,
        output_keys,
        mint_url,
        unit,
    })
}

/// Prepare a SIG_ALL spend request from proofs that are already P2PK-locked.
///
/// Use this when the wallet minted directly to locked proofs (skipping the
/// intermediate "lock via swap" step).
pub async fn prepare_sigall_spend(
    wallet: &Wallet,
    locked_proofs: Proofs,
) -> DemoResult<PreparedSigAllSwap> {
    let input_amount = locked_proofs.total_amount()?;
    let input_fee = wallet.get_proofs_fee(&locked_proofs).await?.total;
    let output_amount = input_amount
        .checked_sub(input_fee)
        .ok_or_else(|| io::Error::other("SIG_ALL demo amount underflow"))?;

    if output_amount == Amount::ZERO {
        return Err(io::Error::other("SIG_ALL demo output amount is zero").into());
    }

    let mint_url = wallet.mint_url.clone();
    let unit = wallet.unit.clone();

    let locked_token = Token::new(
        mint_url.clone(),
        locked_proofs.clone(),
        Some("P2PK SIG_ALL locked token".to_string()),
        unit.clone(),
    );
    let locked_token_string = locked_token.to_string();

    let active_keyset = wallet.get_active_keyset().await?;
    let fee_and_amounts = wallet
        .get_keyset_fees_and_amounts_by_id(active_keyset.id)
        .await?;
    let output_keys = wallet.load_keyset_keys(active_keyset.id).await?;
    let output_premint = PreMintSecrets::random(
        active_keyset.id,
        output_amount,
        &SplitTarget::default(),
        &fee_and_amounts,
    )?;
    let unsigned_swap_request =
        SwapRequest::new(locked_proofs.clone(), output_premint.blinded_messages());

    Ok(PreparedSigAllSwap {
        lock_amount: input_amount,
        lock_swap_fee: Amount::ZERO,
        locked_token,
        locked_token_string,
        locked_proofs,
        input_amount,
        input_fee,
        output_amount,
        unsigned_swap_request,
        output_premint,
        output_keys,
        mint_url,
        unit,
    })
}

impl PreparedSigAllSwap {
    pub fn sig_all_message(&self) -> String {
        self.unsigned_swap_request.sig_all_msg_to_sign()
    }

    pub fn signing_payload(&self) -> SigAllSigningPayload {
        let message = self.sig_all_message();
        let digest = sha256::Hash::hash(message.as_bytes());

        SigAllSigningPayload {
            message,
            digest_hex: digest.to_string(),
        }
    }

    pub fn build_signed_swap(
        &self,
        payload: &SigAllSigningPayload,
        signature_hex: String,
    ) -> DemoResult<SignedSigAllSwap> {
        let request =
            swap_request_with_signature_hex(&self.unsigned_swap_request, signature_hex.clone())?;

        Ok(SignedSigAllSwap {
            request,
            message: payload.message.clone(),
            digest_hex: payload.digest_hex.clone(),
            signature_hex,
        })
    }

    pub async fn execute_signed_swap(
        &self,
        connector: Arc<dyn MintConnector + Send + Sync>,
        signed_swap: SignedSigAllSwap,
    ) -> DemoResult<CompletedSigAllSwap> {
        signed_swap.request.verify_spending_conditions()?;

        let swap_response = connector.post_swap(signed_swap.request.clone()).await?;
        let unlocked_proofs = construct_proofs(
            swap_response.signatures,
            self.output_premint.rs(),
            self.output_premint.secrets(),
            &self.output_keys,
        )?;
        let unlocked_token = Token::new(
            self.mint_url.clone(),
            unlocked_proofs.clone(),
            Some("Unlocked via SIG_ALL swap demo".to_string()),
            self.unit.clone(),
        );

        Ok(CompletedSigAllSwap {
            signed_swap,
            unlocked_proofs,
            unlocked_token,
        })
    }
}

pub fn swap_request_with_signature_hex(
    request: &SwapRequest,
    signature_hex: String,
) -> DemoResult<SwapRequest> {
    let mut signed_request = request.clone();
    add_signature_to_first_input(&mut signed_request, signature_hex)?;
    Ok(signed_request)
}

fn add_signature_to_first_input(
    request: &mut SwapRequest,
    signature_hex: String,
) -> DemoResult<()> {
    let first_input = request
        .inputs_mut()
        .first_mut()
        .ok_or_else(|| io::Error::other("swap request has no inputs"))?;

    match first_input.witness.as_mut() {
        Some(witness) => witness.add_signatures(vec![signature_hex]),
        None => {
            first_input.witness = Some(Witness::P2PKWitness(P2PKWitness {
                signatures: vec![signature_hex],
            }));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Melt (pay a Lightning invoice from FROST-locked proofs)
// ---------------------------------------------------------------------------

/// A prepared melt request ready for FROST signing.
#[derive(Debug, Clone)]
pub struct PreparedSigAllMelt {
    pub quote: MeltQuote,
    pub locked_proofs: Proofs,
    pub input_amount: Amount,
    pub unsigned_melt_request: MeltRequest<String>,
}

/// A signed melt request ready for submission.
#[derive(Debug, Clone)]
pub struct SignedSigAllMelt {
    pub request: MeltRequest<String>,
    pub message: String,
    pub digest_hex: String,
    pub signature_hex: String,
}

/// The result of a completed melt operation.
#[derive(Debug, Clone)]
pub struct CompletedSigAllMelt {
    pub signed_melt: SignedSigAllMelt,
    pub response: MeltQuoteBolt11Response<String>,
}

/// Get a melt quote from the mint for a Bolt11 invoice.
pub async fn get_melt_quote(
    wallet: &Wallet,
    bolt11: &str,
) -> DemoResult<MeltQuote> {
    let quote = wallet
        .melt_quote(PaymentMethod::BOLT11, bolt11, None, None)
        .await?;
    Ok(quote)
}

/// Prepare a SIG_ALL melt request from already-locked proofs and a melt quote.
pub fn prepare_sigall_melt(
    quote: MeltQuote,
    locked_proofs: Proofs,
) -> DemoResult<PreparedSigAllMelt> {
    let input_amount = locked_proofs.total_amount()?;
    let unsigned_melt_request =
        MeltRequest::new(quote.id.clone(), locked_proofs.clone(), None);

    Ok(PreparedSigAllMelt {
        quote,
        locked_proofs,
        input_amount,
        unsigned_melt_request,
    })
}

impl PreparedSigAllMelt {
    /// Get the SIG_ALL message for the melt request.
    pub fn sig_all_message(&self) -> String {
        self.unsigned_melt_request.sig_all_msg_to_sign()
    }

    /// Compute the signing payload (message + SHA-256 digest).
    pub fn signing_payload(&self) -> SigAllSigningPayload {
        let message = self.sig_all_message();
        let digest = sha256::Hash::hash(message.as_bytes());

        SigAllSigningPayload {
            message,
            digest_hex: digest.to_string(),
        }
    }

    /// Inject the FROST signature into the melt request.
    pub fn build_signed_melt(
        &self,
        payload: &SigAllSigningPayload,
        signature_hex: String,
    ) -> DemoResult<SignedSigAllMelt> {
        let request = melt_request_with_signature_hex(
            &self.unsigned_melt_request,
            signature_hex.clone(),
        )?;

        Ok(SignedSigAllMelt {
            request,
            message: payload.message.clone(),
            digest_hex: payload.digest_hex.clone(),
            signature_hex,
        })
    }

    /// Submit the signed melt request to the mint.
    pub async fn execute_signed_melt(
        &self,
        connector: Arc<dyn MintConnector + Send + Sync>,
        signed_melt: SignedSigAllMelt,
    ) -> DemoResult<CompletedSigAllMelt> {
        signed_melt.request.verify_spending_conditions()?;

        let response = connector
            .post_melt(&PaymentMethod::BOLT11, signed_melt.request.clone())
            .await?;

        Ok(CompletedSigAllMelt {
            signed_melt,
            response,
        })
    }
}

fn melt_request_with_signature_hex(
    request: &MeltRequest<String>,
    signature_hex: String,
) -> DemoResult<MeltRequest<String>> {
    let mut signed_request = request.clone();
    let first_input = signed_request
        .inputs_mut()
        .first_mut()
        .ok_or_else(|| io::Error::other("melt request has no inputs"))?;

    match first_input.witness.as_mut() {
        Some(witness) => witness.add_signatures(vec![signature_hex]),
        None => {
            first_input.witness = Some(Witness::P2PKWitness(P2PKWitness {
                signatures: vec![signature_hex],
            }));
        }
    }

    Ok(signed_request)
}
