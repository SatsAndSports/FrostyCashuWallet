_Very basic proof-of-concept. This uses FROST signatures, coordinated over Nostr, to sign a Cashu transaction which spends collaboratively from the wallet via the threshold signatures (e.g. 3-of-5) of FROST. This includes a basic web app where the signers can approve the signature and construct their signatures via Nostr. However, everything else is very hacky in this and therefore it's not really useful; feel free to take the idea and run with it! [demo video](https://youtu.be/YuLX1ua0dt0)._

# Frosty Cashu Wallet

Collaborative threshold ecash, built on the [Cashu Development Kit (CDK)](https://github.com/cashubtc/cdk).

This is a fork of CDK that adds **FROST threshold signing** coordinated over **Nostr**, allowing a group of participants to collectively control Cashu ecash tokens.

## Motivation

Standard Cashu tokens are bearer assets: anyone with the secret can spend them. Frosty Cashu introduces collaborative custody using [FROST](https://eprint.iacr.org/2020/852) (Flexible Round-Optimized Schnorr Threshold Signatures).

- **Shared treasuries**: A group manages a pool of ecash where no single member can spend unilaterally.
- **Multi-device security**: Require signatures from both your laptop and your phone before funds can move.
- **Interactive governance**: Force a human-in-the-loop approval process for every spend.

The final signature is a standard 64-byte BIP-340 Schnorr signature, indistinguishable from a single-signer signature. The mint never knows a threshold group was involved.

## How It Works

1. **P2PK locking** ([NUT-11](https://github.com/cashubtc/nuts/blob/main/11.md)): Ecash tokens are locked to a public key derived from a FROST threshold group.
2. **SIG_ALL**: The spending condition requires a single signature that covers all inputs and outputs of the request, binding the signature to a specific transaction intent.
3. **FROST signing** (`frost-secp256k1-tr`): A dealer splits a secret key into shares distributed to N participants. Any T-of-N subset can collaborate to produce a valid signature.
4. **Nostr transport**: Signing rounds are coordinated over Nostr relays using custom ephemeral events. Participants can be anywhere in the world.

## Quick Start

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) toolchain (1.85+, pinned to 1.93.0)
- A Nostr relay (defaults to `wss://mls-push.satsandsports.cash`)

### Example 1: Automated Local Swap

The simplest way to see FROST in action. The CLI splits a secret into a 2-of-3 threshold group, spawns local signer tasks, mints ecash locked to the group, coordinates a FROST signing session, and swaps the locked tokens back to unlocked ecash.

```bash
cargo run --example p2pk-sigall-demo
```

The output will show each step: key generation, minting, the SIG_ALL message, the SHA-256 digest, nonce commitments, signature shares, the aggregated signature, and the final unlocked token.

### Example 2: Automated Local Melt

Same as above, but instead of swapping to unlocked ecash, the group pays a Lightning invoice. Pass a Bolt11 invoice as an argument:

```bash
cargo run --example p2pk-sigall-demo -- lnbc100n1p...
```

The CLI will fetch a melt quote from the mint, mint the exact amount needed into locked proofs, coordinate the FROST signature, and submit the payment.

### Example 3: Interactive Swap with Real People

In interactive mode, the CLI prints JSON packages that you distribute to participants (e.g., via Signal). They use the Frosty Signer web app to join the session and approve each signing round.

```bash
cargo run --example p2pk-sigall-demo -- --interactive
```

1. Copy each **Signer Package** (JSON block) printed by the CLI.
2. Send each one to a different participant.
3. Each participant opens the [Frosty Signer Web App](https://satsandsports.github.io/FrostyCashuWallet/) and pastes their package.
4. They click **Join Session**.
5. Once enough signers have joined (at or above the threshold), press **ENTER** in the coordinator terminal.
6. Each participant clicks **Approve & Commit Nonces** (Round 1).
7. Each participant clicks **Finalize Signature** (Round 2).
8. The coordinator aggregates the shares and submits the swap.

### Example 4: Interactive Melt with Real People

Combine interactive mode with a Lightning payment:

```bash
cargo run --example p2pk-sigall-demo -- --interactive lnbc100n1p...
```

The same human coordination flow applies, but the final action pays a real Lightning invoice instead of swapping tokens.

### Example 5: Large Groups

Configure the threshold and participant count for larger groups:

```bash
cargo run --example p2pk-sigall-demo -- --interactive --threshold 6 --max 10
```

You can distribute 10 packages, and proceed as soon as any 6 participants have joined. The coordinator presses ENTER to start the session with whatever subset is available (as long as it meets the threshold).

## CLI Flags

| Flag | Description | Default |
|---|---|---|
| `--interactive` | Wait for real participants via the web app | off (local tasks) |
| `--threshold T` | Minimum signers required | 2 |
| `--max N` | Total number of participants | 3 |
| `--mint-url URL` | Cashu mint URL | `https://mint.minibits.cash/Bitcoin` |
| `--relays URLS` | Comma-separated Nostr relay URLs | `wss://mls-push.satsandsports.cash` |
| `--nsec NSEC` | Source secret key (Nostr nsec format) | built-in demo key |
| `--coordinator-nsec NSEC` | Coordinator Nostr key | random per run |
| `--lock-amount SATS` | Amount to lock (swap mode) | 10 |
| `--fund-amount SATS` | Total funding amount (swap mode) | lock_amount + 4 |

Environment variable `CDK_LEGACY_SIG_ALL=1` enables the older SIG_ALL message format for compatibility with mints that have not yet updated to include `C` and `amount` fields.

## Frosty Signer Web App

The web app is a pure Rust/WASM application built with Leptos. It runs entirely in the browser with no server backend. The FROST cryptography executes in WebAssembly using the same `frost-secp256k1-tr` crate as the CLI.

The web app reads the relay URLs from the JSON package, so it automatically connects to the same relay as the coordinator.

### Building

```bash
cd frost-web
make deploy
```

This compiles the WASM, bundles it with Trunk, and copies the static assets to `docs/` for GitHub Pages.

### Local Testing

```bash
cd frost-web/dist
python3 -m http.server 8080
```

Open multiple browser windows at `http://127.0.0.1:8080` to simulate different participants.

### Hosting

The `docs/` directory is served by GitHub Pages. After rebuilding, commit and push:

```bash
git add docs/
git commit -m "rebuild frost-web"
git push
```

## Nostr Protocol

Frosty Cashu uses custom ephemeral Nostr event kinds for coordination:

| Kind | Purpose |
|---|---|
| 23100 | Signer Provisioned (one-off join acknowledgment) |
| 23102 | Round 1 Request (coordinator publishes digest and roster) |
| 23103 | Round 1 Response (signer publishes nonce commitments) |
| 23104 | Round 2 Request (coordinator publishes signing package) |
| 23105 | Round 2 Response (signer publishes signature share) |

Session isolation is achieved through unique `session_id` tags on each event. Provisioning uses a unique `provisioning_id` per run to prevent interference from relay-cached events.

## Cryptographic Details

- **Ciphersuite**: `frost-secp256k1-tr` (BIP-340 compatible Schnorr signatures with Even-Y normalization)
- **Hashing boundary**: CDK's signature verification pre-hashes the message with SHA-256. The FROST signing package therefore signs `sha256(sig_all_msg_to_sign().as_bytes())`, not the raw message bytes.
- **Signature size**: Always 64 bytes, regardless of threshold or group size.
- **Practical limits**: The protocol supports thousands of participants. For interactive demos, 6-of-10 or 11-of-20 are practical sweet spots.

## Project Structure

### Added Files

| File | Purpose |
|---|---|
| `crates/cdk/examples/p2pk-sigall-demo.rs` | Main demo binary (swap, melt, interactive) |
| `crates/cdk/examples/support/frost_nostr.rs` | FROST key splitting, Nostr coordination, signer tasks |
| `crates/cdk/examples/support/p2pk_sigall_swap.rs` | Cashu P2PK locking, swap/melt request construction |
| `crates/cdk-integration-tests/tests/frost_sigall_swap.rs` | Automated regression tests |
| `frost-web/` | Frosty Signer web app (Leptos + WASM) |
| `docs/` | Static assets for GitHub Pages |
| `FROSTY_CASHU.md` | Detailed developer log and protocol notes |

### Modified Files

| File | Change |
|---|---|
| `crates/cashu/src/nuts/nut03.rs` | Added `CDK_LEGACY_SIG_ALL` toggle to `SwapRequest::sig_all_msg_to_sign` |
| `crates/cashu/src/nuts/nut05.rs` | Added `CDK_LEGACY_SIG_ALL` toggle to `MeltRequest::sig_all_msg_to_sign` |

## Running Tests

```bash
CDK_TEST_DB_TYPE=memory cargo test -p cdk-integration-tests --test frost_sigall_swap -- --test-threads 1
```

The tests verify:
- The FROST group public key matches the source secret at the x-only level.
- Unsigned SIG_ALL requests correctly fail verification.
- FROST-signed requests pass local verification and succeed against an in-memory mint.
- Signing the raw message bytes (without SHA-256 pre-hashing) produces an invalid signature.

## Upstream

This project is a fork of the [Cashu Development Kit](https://github.com/cashubtc/cdk). See the upstream repository for documentation on the full CDK library, mint daemon, CLI wallet, and NUT specifications.

## License

Code is under the [MIT License](LICENSE).
