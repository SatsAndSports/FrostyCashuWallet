use std::io;
use std::sync::Arc;

use bitcoin::hashes::{sha256, Hash};
use cdk::amount::SplitTarget;
use cdk::dhke::construct_proofs;
use cdk::mint_url::MintUrl;
use cdk::nuts::nut00::ProofsMethods;
use cdk::nuts::{
    Conditions, CurrencyUnit, Keys, P2PKWitness, PreMintSecrets, Proofs, PublicKey, SecretKey,
    SigFlag, SpendingConditionVerification, SpendingConditions, SwapRequest, Token, Witness,
};
use cdk::wallet::{MintConnector, SendOptions, Wallet};
use cdk::Amount;

pub type DemoResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub const CHEAT_SECRET_HEX: &str =
    "e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734";
pub const DEFAULT_LOCK_AMOUNT_SATS: u64 = 13;

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

impl PreparedSigAllSwap {
    pub fn manually_sign(&self, secret_key: &SecretKey) -> DemoResult<SignedSigAllSwap> {
        let mut request = self.unsigned_swap_request.clone();
        let message = request.sig_all_msg_to_sign();
        let digest_hex = sha256::Hash::hash(message.as_bytes()).to_string();
        let signature_hex = secret_key.sign(message.as_bytes())?.to_string();

        add_signature_to_first_input(&mut request, signature_hex.clone())?;

        Ok(SignedSigAllSwap {
            request,
            message,
            digest_hex,
            signature_hex,
        })
    }

    pub fn built_in_sig_all_signature(&self, secret_key: &SecretKey) -> DemoResult<String> {
        let mut request = self.unsigned_swap_request.clone();
        request.sign_sig_all(secret_key.clone())?;
        first_signature_hex(&request)
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
            Some("Unlocked via manual SIG_ALL swap".to_string()),
            self.unit.clone(),
        );

        Ok(CompletedSigAllSwap {
            signed_swap,
            unlocked_proofs,
            unlocked_token,
        })
    }
}

pub fn first_signature_hex(request: &SwapRequest) -> DemoResult<String> {
    request
        .inputs()
        .first()
        .and_then(|proof| proof.witness.as_ref())
        .and_then(Witness::signatures)
        .and_then(|signatures| signatures.into_iter().next())
        .ok_or_else(|| io::Error::other("missing first SIG_ALL signature").into())
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
