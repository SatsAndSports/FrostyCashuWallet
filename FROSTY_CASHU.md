# FROSTY_CASHU

## Purpose

This note captures the current state of the Cashu FROST demo work in the CDK repo so we can resume cleanly later.

The near-term goal is:

1. lock ecash to a pubkey with NUT-11 P2PK
2. spend it with `SIG_ALL`
3. expose the exact message being signed
4. later replace the cheat signer with real FROST signing

For now, the first working step is a swap-only demo that cheats by using a known private key instead of threshold signing.

## Current Status

Working today:

- a new example builds a P2PK `SIG_ALL` locked token, reconstructs the locked proofs, builds a raw `SwapRequest`, prints the `SIG_ALL` message and digest, manually signs it, injects the witness, and submits the swap
- a pure integration test verifies the unsigned request fails and the manually signed request succeeds
- the example defaults to `https://fake.thesimplekid.dev`
- the automated test does not use the remote fake mint; it uses a local in-memory mint through `DirectMintConnection`

Not implemented yet:

- FROST signing
- melt support in this demo flow
- a generic signer trait beyond the current helper boundary

## Files Added / Changed

### New example

- `crates/cdk/examples/p2pk-sigall-swap.rs`
- `crates/cdk/examples/support/p2pk_sigall_swap.rs`

### New test

- `crates/cdk-integration-tests/tests/frost_sigall_swap.rs`

### Example registration

- `crates/cdk/Cargo.toml`

## What The Example Does

The example in `crates/cdk/examples/p2pk-sigall-swap.rs`:

1. creates a wallet
2. funds it from the mint
3. derives a cheat signer from a fixed secret, optionally overridden by `NOSTR_NSEC`
4. locks a token to that signer pubkey with `SpendingConditions::new_p2pk(..., SIG_ALL)`
5. parses the token back into proofs instead of using `wallet.receive()`
6. constructs an unsigned `SwapRequest`
7. prints:
   - the canonical `SIG_ALL` message
   - the SHA-256 prehash of that message
   - the manual signature hex
8. injects the signature into the first input witness
9. submits the raw swap
10. reconstructs and prints the unlocked token

## Helper Layout

Most of the reusable logic is in `crates/cdk/examples/support/p2pk_sigall_swap.rs`.

Important pieces:

- `prepare_p2pk_sigall_swap(...)`
  - locks ecash to a P2PK `SIG_ALL` pubkey
  - reconstructs locked proofs from the token
  - computes spend-side input fee
  - builds unsigned swap outputs and an unsigned `SwapRequest`

- `PreparedSigAllSwap::manually_sign(...)`
  - gets `request.sig_all_msg_to_sign()`
  - hashes it with SHA-256
  - signs using the cheat signer
  - attaches the signature to the first input witness

- `PreparedSigAllSwap::execute_signed_swap(...)`
  - posts the raw signed swap through a `MintConnector`
  - reconstructs the returned proofs
  - returns an unlocked token

This is the seam to replace later with FROST.

## Why This Is Set Up For FROST Later

The important design decision is that we do not hide signing inside `wallet.receive()` or only call `sign_sig_all()` and stop there.

Instead, the helper explicitly exposes:

- the canonical request-level message
- the exact digest we sign
- the witness injection step

That means later we can replace:

- current: `secret_key.sign(message.as_bytes())`
- future: `frost_sign(digest) -> schnorr_signature_hex`

without changing the rest of the swap flow.

## Cheat Signer Details

The current cheat signer uses this fixed hex secret:

- `e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734`

The example converts it to a Nostr `nsec` by default so the demo feels closer to the intended UX.

Important caveat:

- `cdk::nuts::SecretKey::from_str()` does not currently parse `nsec` directly in practice
- so the example parses `NOSTR_NSEC` with `nostr-sdk`, then converts the bytes into `cdk::nuts::SecretKey`

## Default Mint Behavior

### Example

By default the example uses:

- `CDK_MINT_URL=https://fake.thesimplekid.dev`

This is convenient for a live demo because minting just works.

### Test

The test in `crates/cdk-integration-tests/tests/frost_sigall_swap.rs` does not use the remote host.

It uses:

- `create_and_start_test_mint()`
- `create_test_wallet_for_mint(...)`
- `DirectMintConnection`

So the automated path is local and deterministic.

## Commands That Passed

### Build the example

```bash
cargo check -p cdk --example p2pk-sigall-swap
```

### Run the pure test

```bash
CDK_TEST_DB_TYPE=memory cargo test -p cdk-integration-tests --test frost_sigall_swap -- --test-threads 1
```

### Run the example

```bash
cargo run -p cdk --example p2pk-sigall-swap
```

## Example Environment Variables

Supported by the example:

- `CDK_MINT_URL`
- `CDK_LOCK_AMOUNT`
- `CDK_FUND_AMOUNT`
- `NOSTR_NSEC`

Defaults:

- mint URL: `https://fake.thesimplekid.dev`
- lock amount: `13`
- fund amount: `lock_amount + 32`
- `NOSTR_NSEC`: derived from the fixed cheat secret above

## What The Test Proves

The test in `crates/cdk-integration-tests/tests/frost_sigall_swap.rs` currently proves:

- the prepared locked token has the expected amount
- the locked proofs total equals the prepared input amount
- unsigned `SIG_ALL` verification fails with `SignaturesNotProvided`
- a manually signed request verifies locally
- the signed request succeeds against a local in-memory mint
- the unlocked output amount matches the expected post-fee amount

One thing the test does not assert anymore:

- byte-for-byte equality between the manual signature and CDK's built-in `sign_sig_all()` signature

Reason:

- both signatures are valid, but Schnorr signing here is randomized, so equal messages under the same key do not necessarily produce identical signature bytes

## Important Notes About The Signing Message

For this demo, the message we display is the request-level `SIG_ALL` message from the Cashu types.

The helper also prints the SHA-256 digest of that message because that is the useful boundary for later threshold signing work.

Practical takeaway:

- the thing to replace with FROST is the step that turns the request message or its digest into a Schnorr signature hex string for the first witness

## Why Swap First

We intentionally deferred melt for now.

Reasons:

- swap keeps Lightning payment behavior out of the critical demo path
- the local pure test is simpler and more deterministic
- the signer abstraction is already request-level, so melt can be added later without rethinking the whole design

## Planned Next Step

Replace the cheat signer with real FROST while keeping the rest of the helper flow the same.

Most likely plan:

1. keep `prepare_p2pk_sigall_swap(...)`
2. keep explicit access to:
   - message
   - digest
   - witness injection
3. swap `manually_sign(...)` internals from:
   - single known secret key
   to:
   - FROST key shares
   - nonce commitments
   - signature shares
   - aggregate Schnorr signature

## After FROST

After the swap path works with FROST, reintroduce melt.

Likely approach:

- reuse the same signer boundary
- build a raw `MeltRequest`
- expose its `SIG_ALL` message
- sign it with the same FROST path
- attach the aggregated signature to the first input witness

## Resume Checklist

If resuming later, start here:

1. inspect `crates/cdk/examples/support/p2pk_sigall_swap.rs`
2. keep the swap flow intact
3. replace only the cheat signing step first
4. prove the FROST signature passes the existing swap test shape
5. only then add melt back in
