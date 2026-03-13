# FROSTY_CASHU

## Purpose

This note captures the current state of the Cashu FROST demo work in the CDK repo so we can resume cleanly later.

The current goal is:

1. lock ecash to a pubkey with NUT-11 P2PK
2. spend it with `SIG_ALL`
3. expose the exact message being signed
4. use real FROST signing coordinated over Nostr
5. add melt later on the same signer boundary

## Current Status

Working today:

- the main swap example coordinates FROST round 1 and round 2 over Nostr, then submits the final Cashu swap locally
- the demo uses real FROST signing with `frost-secp256k1-tr`
- the threshold group is a deterministic 2-of-3 split of the existing known demo secret
- the example builds a P2PK `SIG_ALL` locked token, reconstructs the locked proofs, builds a raw `SwapRequest`, prints the canonical message and its SHA-256 digest, aggregates a FROST signature via Nostr, injects the witness, and submits the swap
- the default example path works against `https://fake.thesimplekid.dev`
- the automated integration tests use a local in-memory mint through `DirectMintConnection`
- there is a regression test proving that FROST must sign `sha256(sig_all_msg_to_sign().as_bytes())`, not the raw request string bytes

Not implemented yet:

- melt support in this demo flow
- DKG or dealer-generated fresh threshold keys
- share persistence or multi-process signing coordination

## Files Added / Changed

### Demo docs

- `FROSTY_CASHU.md`

### Example

- `crates/cdk/examples/p2pk-sigall-swap.rs`
- `crates/cdk/examples/support/frost_nostr.rs`
- `crates/cdk/examples/support/p2pk_sigall_swap.rs`

### Test

- `crates/cdk-integration-tests/tests/frost_sigall_swap.rs`

### Dependencies / registration

- `Cargo.toml`
- `crates/cdk/Cargo.toml`
- `crates/cdk-integration-tests/Cargo.toml`

## What The Example Does

The example in `crates/cdk/examples/p2pk-sigall-swap.rs`:

1. parses a source `nsec` into a Cashu secret key
2. splits that secret into a deterministic 2-of-3 FROST group via `dealer_setup`
3. provisions the signers over Nostr: spawns signer tasks and waits for each one to publish a `SignerProvisioned` (Kind 23100) acknowledgment — this is a one-off step, not per session
4. creates a wallet and funds it from the mint
5. locks a token to the FROST group pubkey with `SpendingConditions::new_p2pk(..., SIG_ALL)`
6. parses the token back into proofs instead of using `wallet.receive()`
7. constructs an unsigned `SwapRequest`
8. coordinates a FROST signing session over Nostr:
   - publishes a round-1 request to the relay
   - collects nonce commitments from whoever responds first (threshold subset)
   - publishes a round-2 signing package to those selected signers
   - collects signature shares
   - aggregates and verifies the final Schnorr signature
9. injects the signature into the first input witness
10. submits the raw swap and reconstructs the unlocked token
11. shuts down the signer tasks

## Helper Layout

The reusable logic lives in two support modules:

### `crates/cdk/examples/support/frost_nostr.rs`

The Nostr transport and FROST coordination layer:

- `dealer_setup(...)` — one-time key split that produces the group pubkey, signer packages, roster, and public key package
- `provision_signers(...)` — spawns signer tasks, waits for each to publish a `SignerProvisioned` (Kind 23100) ack over Nostr; returns a `ProvisionedSigners` handle for later shutdown
- `sign_message_via_nostr(...)` — coordinates a single signing session (round-1 + round-2) over Nostr using already-provisioned signers; returns the final signature hex

### `crates/cdk/examples/support/p2pk_sigall_swap.rs`

The Cashu swap preparation and execution layer:

- `prepare_p2pk_sigall_swap(...)` — locks ecash to a P2PK `SIG_ALL` pubkey, reconstructs locked proofs, computes fees, and builds an unsigned `SwapRequest`
- `PreparedSigAllSwap::signing_payload()` — exposes the canonical `SIG_ALL` message and its SHA-256 digest
- `PreparedSigAllSwap::build_signed_swap(...)` — injects a signature hex into the witness
- `PreparedSigAllSwap::execute_signed_swap(...)` — posts the signed swap and reconstructs unlocked proofs

## Why `frost-secp256k1-tr`

CDK verifies BIP340/x-only Schnorr signatures. `frost-secp256k1-tr` produces compatible 64-byte signatures.

CDK's `SecretKey::sign()` and `PublicKey::verify()` each hash the input bytes once with SHA-256 before the Schnorr operation. So the correct FROST message is:

- `sha256(sig_all_msg_to_sign().as_bytes())`

not:

- `sig_all_msg_to_sign().as_bytes()`

## Key Material Strategy

The threshold group is built from the existing known demo secret using `frost::keys::split()`. This keeps the demo deterministic and easy to compare with a single-key flow.

Constants in `crates/cdk/examples/support/frost_nostr.rs`:

- source secret hex: `DEMO_SECRET_HEX`
- default threshold: `DEFAULT_THRESHOLD` (2)
- default participant count: `DEFAULT_MAX_SIGNERS` (3)

## Converting The FROST Pubkey To Cashu

The demo converts the FROST verifying key into a Cashu `PublicKey` by:

1. normalizing to even-Y with the FROST helper
2. serializing the compressed SEC1 form
3. feeding those bytes into `cdk::nuts::PublicKey::from_slice(...)`

## Nostr Protocol

The demo uses plain custom ephemeral Nostr event kinds:

- `23100` — signer provisioned (one-off: signers acknowledge receipt of their dealer package)
- `23102` — round-1 request (coordinator publishes digest and participant roster)
- `23103` — round-1 commitment response (signers publish nonce commitments)
- `23104` — round-2 signing package (coordinator publishes selected signer set and signing package)
- `23105` — round-2 signature share response (selected signers publish signature shares)

Session events (`23102`-`23105`) carry a `["d", session_id]` tag for filtering.

Signer identity is verified by checking the Nostr event author against the expected `participant_id -> nostr pubkey` roster maintained by the coordinator.

## Provisioning vs Sessions

**Provisioning** is a one-off step that happens before any signing session. The dealer distributes packages to each signer, and each signer acknowledges receipt by publishing a `SignerProvisioned` (Kind 23100) event. The coordinator waits for all acknowledgments before proceeding. After provisioning, the signers remain connected and ready to handle multiple sessions.

A **session** is one signing operation. Each session has a unique `session_id` and produces one aggregate Schnorr signature. If the group wants to sign multiple swaps or melts with the same FROST key shares, each operation is a separate session with fresh nonces. Reusing nonces across sessions would leak the private key shares.

The typical lifecycle is:

1. **provisioning (once)**: dealer creates packages, signers connect and publish Kind 23100 acks
2. **session (per operation)**:
   - coordinator generates a `session_id`
   - coordinator publishes the round-1 request
   - signers respond with nonce commitments
   - coordinator selects a threshold subset from whoever responds first
   - coordinator publishes the round-2 signing package to selected signers
   - selected signers respond with signature shares
   - coordinator aggregates the final Schnorr signature
3. **shutdown**: coordinator aborts signer tasks when done

## Default Mint Behavior

### Example

By default the example uses `CDK_MINT_URL=https://fake.thesimplekid.dev`.

### Tests

The integration tests use `create_and_start_test_mint()` with `DirectMintConnection`, so they are local and deterministic.

## Commands

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

## Environment Variables

- `CDK_MINT_URL` — mint URL (default: `https://fake.thesimplekid.dev`)
- `CDK_LOCK_AMOUNT` — amount to lock in sats (default: `13`)
- `CDK_FUND_AMOUNT` — amount to fund the wallet (default: `lock_amount + 32`)
- `CDK_FROST_MAX_SIGNERS` — number of FROST participants (default: `3`)
- `CDK_FROST_THRESHOLD` — signing threshold (default: `2`)
- `CDK_FROST_SESSION_ID` — optional fixed session ID
- `NOSTR_NSEC` — source secret as a Nostr nsec (default: derived from `DEMO_SECRET_HEX`)
- `NOSTR_RELAY_URL` — relay URL (default: `ws://127.0.0.1:7777`)
- `NOSTR_COORDINATOR_NSEC` — coordinator Nostr key (default: random)
- `NOSTR_FROST_TIMEOUT_SECS` — timeout for Nostr round collection (default: `10`)

## What The Tests Prove

- the FROST group pubkey matches the source secret at the x-only level
- the prepared locked token has the expected amount
- unsigned `SIG_ALL` verification fails with `SignaturesNotProvided`
- a FROST-signed request verifies locally
- the signed request succeeds against a local in-memory mint
- the unlocked output amount matches the expected post-fee amount
- signing the raw `sig_all_msg_to_sign()` bytes with FROST is wrong
- signing the SHA-256 digest of that message is correct

## Next Logical Step

Harden the Nostr-backed end-to-end swap path.

Most likely plan:

1. add better failure handling around missing signers and relay timeouts
2. reduce demo-only assumptions in the signer package flow
3. keep the same signer boundary for any future expansion

## Resume Checklist

If resuming later, start here:

1. inspect `crates/cdk/examples/support/p2pk_sigall_swap.rs` and `crates/cdk/examples/support/frost_nostr.rs`
2. keep the signer boundary as message -> SHA-256 digest -> witness hex
3. reuse the FROST group helper for melt
4. build raw melt requests directly rather than hiding inside higher-level wallet flows
5. keep the digest regression test pattern when adding melt
