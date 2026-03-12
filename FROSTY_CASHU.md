# FROSTY_CASHU

## Purpose

This note captures the current state of the Cashu FROST demo work in the CDK repo so we can resume cleanly later.

The current goal is:

1. lock ecash to a pubkey with NUT-11 P2PK
2. spend it with `SIG_ALL`
3. expose the exact message being signed
4. use real FROST signing for the swap path
5. add melt later on the same signer boundary

## Current Status

Working today:

- the swap-only demo now uses real FROST signing with `frost-secp256k1-tr`
- the threshold group is a deterministic 2-of-3 split of the existing known demo secret
- the example builds a P2PK `SIG_ALL` locked token, reconstructs the locked proofs, builds a raw `SwapRequest`, prints the canonical message and its SHA-256 digest, aggregates a FROST signature, injects the witness, and submits the swap
- the default example path works against `https://fake.thesimplekid.dev`
- the automated integration tests use a local in-memory mint through `DirectMintConnection`
- there is a regression test proving that FROST must sign `sha256(sig_all_msg_to_sign().as_bytes())`, not the raw request string bytes

Not implemented yet:

- melt support in this demo flow
- DKG or dealer-generated fresh threshold keys for the demo
- share persistence or multi-process signing coordination

## Files Added / Changed

### Demo docs

- `FROSTY_CASHU.md`

### Example

- `crates/cdk/examples/frost-nostr-smoke.rs`
- `crates/cdk/examples/p2pk-sigall-swap.rs`
- `crates/cdk/examples/support/p2pk_sigall_swap.rs`

### Test

- `crates/cdk-integration-tests/tests/frost_sigall_swap.rs`

### Dependencies / registration

- `Cargo.toml`
- `crates/cdk/Cargo.toml`
- `crates/cdk-integration-tests/Cargo.toml`

## What The Example Does

The example in `crates/cdk/examples/p2pk-sigall-swap.rs`:

1. creates a wallet
2. funds it from the mint
3. parses a source `nsec` into a Cashu secret key
4. splits that secret into a deterministic 2-of-3 FROST group
5. converts the FROST group verifying key into a Cashu `PublicKey`
6. locks a token to that pubkey with `SpendingConditions::new_p2pk(..., SIG_ALL)`
7. parses the token back into proofs instead of using `wallet.receive()`
8. constructs an unsigned `SwapRequest`
9. prints:
   - the canonical `SIG_ALL` message
   - the SHA-256 prehash of that message
   - the aggregated FROST Schnorr signature hex
10. injects the signature into the first input witness
11. submits the raw swap
12. reconstructs and prints the unlocked token

## Helper Layout

Most of the reusable logic is in `crates/cdk/examples/support/p2pk_sigall_swap.rs`.

Important pieces:

- `FrostDemoGroup::from_existing_secret(...)`
  - takes the existing known demo secret
  - deserializes it into a FROST signing key
  - uses `frost::keys::split()` to create a 2-of-3 threshold group
  - exposes the group public key as a Cashu `PublicKey`

- `prepare_p2pk_sigall_swap(...)`
  - locks ecash to a P2PK `SIG_ALL` pubkey
  - reconstructs locked proofs from the token
  - computes spend-side input fee
  - builds unsigned swap outputs and an unsigned `SwapRequest`

- `PreparedSigAllSwap::sign_with_frost(...)`
  - gets `request.sig_all_msg_to_sign()`
  - computes `sha256(message.as_bytes())`
  - runs FROST round 1 / round 2 / aggregate over that 32-byte digest
  - serializes the final Schnorr signature to witness hex
  - attaches the signature to the first input witness

- `PreparedSigAllSwap::execute_signed_swap(...)`
  - posts the raw signed swap through a `MintConnector`
  - reconstructs the returned proofs
  - returns an unlocked token

- `frost_signature_hex(...)`
  - low-level helper that signs arbitrary bytes with the threshold group
  - useful for tests, especially the digest-vs-raw-message regression check

## Current FROST Design

The important design decision is still the same:

- do not hide signing inside `wallet.receive()`
- do not rely only on `sign_sig_all()`

Instead, the helper explicitly exposes:

- the canonical request-level message
- the exact SHA-256 digest bytes that must be signed
- the witness injection step

That means later we can reuse the same flow for melt.

## Why `frost-secp256k1-tr`

The demo uses `frost-secp256k1-tr` because CDK verifies BIP340/x-only Schnorr signatures.

Relevant compatibility facts:

- CDK `SecretKey::sign()` hashes the input bytes once with SHA-256 before Schnorr signing
- CDK `PublicKey::verify()` hashes the input bytes once with SHA-256 before Schnorr verification
- `frost-secp256k1-tr` produces a BIP340-compatible 64-byte Schnorr signature

So the correct FROST message is:

- `sha256(sig_all_msg_to_sign().as_bytes())`

not:

- `sig_all_msg_to_sign().as_bytes()`

## Key Material Strategy

The current threshold group is intentionally built from the existing known demo secret.

Why:

- smallest migration from the earlier cheat-signer path
- deterministic demo behavior
- easy comparison with the prior single-secret flow

Current constants in `crates/cdk/examples/support/p2pk_sigall_swap.rs`:

- source secret hex: `DEMO_SECRET_HEX`
- threshold: `2`
- participant count: `3`

## Converting The FROST Pubkey To Cashu

The demo converts the FROST verifying key into a Cashu `PublicKey` by:

1. normalizing to even-Y with the FROST helper
2. serializing the compressed SEC1 form
3. feeding those bytes into `cdk::nuts::PublicKey::from_slice(...)`

This works because Cashu expects a compressed secp256k1 public key, while verification uses x-only Schnorr internally.

## Default Mint Behavior

### Example

By default the example uses:

- `CDK_MINT_URL=https://fake.thesimplekid.dev`

This is convenient for a live demo because minting and swapping just work.

### Tests

The integration test in `crates/cdk-integration-tests/tests/frost_sigall_swap.rs` does not use the remote host.

It uses:

- `create_and_start_test_mint()`
- `create_test_wallet_for_mint(...)`
- `DirectMintConnection`

So the automated path is local and deterministic.

## Nostr Smoke Step

Before moving FROST signing rounds onto Nostr, there is now a minimal local relay smoke example:

- `crates/cdk/examples/frost-nostr-smoke.rs`

It is intentionally simpler than the swap demo:

1. the coordinator and one signer run in the same process
2. both connect to a local relay, defaulting to `ws://127.0.0.1:7777`
3. a trusted-dealer-style signer package includes a demo `nostr_nsec`
4. the coordinator publishes a custom-kind request event with a `session_id` and `digest_hex`
5. the signer subscribes, sees the request, and publishes a matching response event
6. the coordinator waits for the reply and verifies the echoed session and digest

This step validates the transport path before moving real FROST round-1 commitments and round-2 signature shares onto Nostr.

## Commands That Passed

### Build the example

```bash
cargo check -p cdk --example p2pk-sigall-swap
```

### Run the integration tests

```bash
CDK_TEST_DB_TYPE=memory cargo test -p cdk-integration-tests --test frost_sigall_swap -- --test-threads 1
```

### Run the example

```bash
cargo run -p cdk --example p2pk-sigall-swap
```

### Run the local Nostr smoke example

```bash
cargo run -p cdk --example frost-nostr-smoke --features nostr
```

## Example Environment Variables

Supported by the example:

- `CDK_MINT_URL`
- `CDK_LOCK_AMOUNT`
- `CDK_FUND_AMOUNT`
- `NOSTR_NSEC`

Supported by the Nostr smoke example:

- `NOSTR_RELAY_URL`
- `NOSTR_SMOKE_TIMEOUT_SECS`
- `NOSTR_COORDINATOR_NSEC`
- `NOSTR_SIGNER_NSEC`

Defaults:

- mint URL: `https://fake.thesimplekid.dev`
- lock amount: `13`
- fund amount: `lock_amount + 32`
- `NOSTR_NSEC`: derived from the fixed demo secret above

## What The Tests Prove

The tests in `crates/cdk-integration-tests/tests/frost_sigall_swap.rs` currently prove:

- the FROST group pubkey matches the source secret at the x-only level
- the prepared locked token has the expected amount
- the locked proofs total equals the prepared input amount
- unsigned `SIG_ALL` verification fails with `SignaturesNotProvided`
- a FROST-signed request verifies locally
- the signed request succeeds against a local in-memory mint
- the unlocked output amount matches the expected post-fee amount
- signing the raw `sig_all_msg_to_sign()` bytes with FROST is wrong
- signing the SHA-256 digest of that message is correct

## Important Signing Detail

The most important detail in the whole demo is this boundary:

- displayed message: `request.sig_all_msg_to_sign()`
- actual bytes given to FROST: `sha256(message.as_bytes())`

If the wrong bytes are signed, CDK rejects the witness even though the FROST signature is internally valid for the wrong message.

## Why Swap First

We intentionally deferred melt for now.

Reasons:

- swap keeps Lightning payment behavior out of the critical signing path
- the local pure test is simpler and more deterministic
- the request-level signer boundary is already in place for later melt support

## Next Logical Step

Move FROST signing rounds onto Nostr now that there is a minimal relay smoke step.

Most likely plan:

1. keep the current `FrostDemoGroup` and signing helpers
2. send round-1 requests and commitments over Nostr
3. send round-2 signing packages and signature shares over Nostr
4. aggregate locally and reuse the existing swap witness injection path
5. once that works, add melt on top of the same signer boundary

## Resume Checklist

If resuming later, start here:

1. inspect `crates/cdk/examples/support/p2pk_sigall_swap.rs`
2. keep the signer boundary as message -> SHA-256 digest -> witness hex
3. reuse the FROST group helper for melt
4. build raw melt requests directly rather than hiding inside higher-level wallet flows
5. keep the digest regression test pattern when adding melt
