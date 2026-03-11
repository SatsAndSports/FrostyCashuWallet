use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
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
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::keys::EvenY;

pub type DemoResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub const DEMO_SECRET_HEX: &str =
    "e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734";
pub const DEFAULT_LOCK_AMOUNT_SATS: u64 = 13;
pub const DEFAULT_FROST_MAX_SIGNERS: u16 = 3;
pub const DEFAULT_FROST_THRESHOLD: u16 = 2;

#[derive(Clone)]
pub struct FrostDemoGroup {
    pub group_public_key: PublicKey,
    pub max_signers: u16,
    pub threshold: u16,
    key_packages: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public_key_package: frost::keys::PublicKeyPackage,
    signer_ids: Vec<frost::Identifier>,
}

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

impl FrostDemoGroup {
    pub fn from_existing_secret(secret_key: &SecretKey) -> DemoResult<Self> {
        Self::from_existing_secret_with_params(
            secret_key,
            DEFAULT_FROST_MAX_SIGNERS,
            DEFAULT_FROST_THRESHOLD,
        )
    }

    pub fn from_existing_secret_with_params(
        secret_key: &SecretKey,
        max_signers: u16,
        threshold: u16,
    ) -> DemoResult<Self> {
        if threshold == 0 || max_signers == 0 || threshold > max_signers {
            return Err(io::Error::other("invalid FROST threshold configuration").into());
        }

        let frost_signing_key = frost::SigningKey::deserialize(secret_key.as_secret_bytes())?;
        let mut rng = frost::rand_core::OsRng;
        let (secret_shares, public_key_package) = frost::keys::split(
            &frost_signing_key,
            max_signers,
            threshold,
            frost::keys::IdentifierList::Default,
            &mut rng,
        )?;
        let key_packages = secret_shares
            .into_iter()
            .map(|(identifier, secret_share)| {
                let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
                Ok((identifier, key_package))
            })
            .collect::<Result<BTreeMap<_, _>, frost::Error>>()?;
        let signer_ids = key_packages
            .keys()
            .copied()
            .take(threshold as usize)
            .collect::<Vec<_>>();

        if signer_ids.len() != threshold as usize {
            return Err(io::Error::other("insufficient FROST signing shares").into());
        }

        let group_public_key =
            frost_verifying_key_to_cashu_public_key(public_key_package.verifying_key())?;

        Ok(Self {
            group_public_key,
            max_signers,
            threshold,
            key_packages,
            public_key_package,
            signer_ids,
        })
    }

    pub fn selected_signer_count(&self) -> usize {
        self.signer_ids.len()
    }
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
    pub fn sig_all_message(&self) -> String {
        self.unsigned_swap_request.sig_all_msg_to_sign()
    }

    pub fn sign_with_frost(&self, frost_group: &FrostDemoGroup) -> DemoResult<SignedSigAllSwap> {
        let message = self.sig_all_message();
        let digest = sha256::Hash::hash(message.as_bytes());
        let signature_hex = frost_signature_hex(digest.as_byte_array(), frost_group)?;
        let request =
            swap_request_with_signature_hex(&self.unsigned_swap_request, signature_hex.clone())?;

        Ok(SignedSigAllSwap {
            request,
            message,
            digest_hex: digest.to_string(),
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

pub fn frost_signature_hex(
    signing_bytes: &[u8],
    frost_group: &FrostDemoGroup,
) -> DemoResult<String> {
    let mut rng = frost::rand_core::OsRng;
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();

    for signer_id in &frost_group.signer_ids {
        let key_package = frost_group
            .key_packages
            .get(signer_id)
            .ok_or_else(|| io::Error::other("missing FROST key package"))?;
        let (signer_nonces, signer_commitments) =
            frost::round1::commit(key_package.signing_share(), &mut rng);
        nonces.insert(*signer_id, signer_nonces);
        commitments.insert(*signer_id, signer_commitments);
    }

    let signing_package = frost::SigningPackage::new(commitments, signing_bytes);
    let mut signature_shares = BTreeMap::new();

    for signer_id in &frost_group.signer_ids {
        let key_package = frost_group
            .key_packages
            .get(signer_id)
            .ok_or_else(|| io::Error::other("missing FROST key package"))?;
        let signer_nonces = nonces
            .get(signer_id)
            .ok_or_else(|| io::Error::other("missing FROST signing nonce"))?;
        let signature_share = frost::round2::sign(&signing_package, signer_nonces, key_package)?;
        signature_shares.insert(*signer_id, signature_share);
    }

    let group_signature = frost::aggregate(
        &signing_package,
        &signature_shares,
        &frost_group.public_key_package,
    )?;
    frost_group
        .public_key_package
        .verifying_key()
        .verify(signing_bytes, &group_signature)?;

    let signature_bytes = group_signature.serialize()?;
    let signature = SchnorrSignature::from_slice(signature_bytes.as_slice())?;

    Ok(signature.to_string())
}

pub fn frost_verifying_key_to_cashu_public_key(
    verifying_key: &frost::VerifyingKey,
) -> DemoResult<PublicKey> {
    let verifying_key = (*verifying_key).into_even_y(None);
    let verifying_key_bytes = verifying_key.serialize()?;

    Ok(PublicKey::from_slice(verifying_key_bytes.as_slice())?)
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
