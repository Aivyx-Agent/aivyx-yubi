# aivyx-yubi: hardware-backed federation identity design

**Status:** approved, ready for implementation planning
**Repos:** `aivyx-yubi` (new standalone repo) + `aivyx` (client integration)

## Motivation

Prompted by a broader concern ("security is becoming a major issue in the
tech/AI space") rather than a specific incident, this scopes the first of
several candidate places a hardware security key (YubiKey) could plug
into the Aivyx ecosystem. Two other candidates — a physical
confirm-to-execute gate on high-risk agent actions, and hardening the
storage master-key unlock with challenge-response — were surfaced during
grounding but explicitly deferred; this project is scoped to the first
only, chosen by the user as the most concrete, lowest-risk starting
point.

`aivyx-federation`'s `Identity` (`crates/aivyx-federation/src/identity.rs`)
is an operator-owned Ed25519 keypair per instance, used to sign every
cross-boundary federation request. Today it's generated in software
(`SigningKey::generate`) and sealed at rest with a key derived from the
storage master key — protected, but the private key material exists on
disk (encrypted) and in process memory whenever the daemon runs. This
project lets the operator instead hold that key in a YubiKey, so the
private key never exists outside the device at all, and every signature
requires a physical touch.

Real crate/hardware landscape was grounded directly before any design
work began, and it ruled out the first obvious-looking path:

- **PIV applet** (the `yubikey` Rust crate) — unmaintained since August
  2023, and its own published docs list only RSA/ECC P-256/P-384, no
  Ed25519. Firmware *does* support Ed25519 in PIV as of 5.7 (2024), but
  the crate hasn't caught up.
- **OpenPGP applet** (the `openpgp-card` crate) — actively maintained
  (last updated July 2026), and Ed25519 support here is much older
  (firmware 5.2.3, 2019), covering far more YubiKeys already in use.

So the real path is the OpenPGP applet via `openpgp-card` +
`card-backend-pcsc`, not PIV — confirmed by direct crate-registry checks,
not assumed from general YubiKey familiarity.

## Out of scope for this project

- The other two candidate use cases surfaced during scoping: a physical
  confirm-to-execute gate on dangerous agent actions, and YubiKey
  challenge-response hardening the storage master-key unlock (the latter
  would also require a formal `DESIGN.md` amendment in `aivyx`, since it
  touches the locked D7 storage contract — a meaningfully heavier project
  than this one). Both are real, independently viable follow-ups, not
  ruled out — just not this project.
- PIV-applet support. Revisit if/when the `yubikey` crate (or an
  alternative) catches up with firmware 5.7's Ed25519 PIV support.
- `aivyx-coder` integration. `aivyx-coder` has no federation identity
  concept at all (no `aivyx-federation`-equivalent crate) — this project
  is `aivyx`-only.
- Replacing the software-generated identity path. This is strictly
  additive — see "Opt-in scope" below.
- Any UI/GUI provisioning flow (a graphical PIN-entry dialog, etc.) —
  provisioning is a CLI subcommand, matching how every other
  operator-facing setup step in `aivyx` works today (`aivyx init`,
  `aivyx access`, `aivyx autonomy`).
- Real hardware verification. This environment has no real YubiKey or
  PC/SC hardware — all testing here is against fakes/mocks. Manual
  verification against a real device is a documented follow-up, not a
  merge blocker (same category as this ecosystem's other hardware/network
  testing gaps).

## Architecture

A new standalone repo, **`aivyx-yubi`** — a focused, hardware/protocol-
facing primitive crate, same shape as `aivyx-confine`/`aivyx-checkpoint`/
`aivyx-kvcache`: one clear concern, consumable by more than one product
later even though `aivyx-federation` is the only consumer today.

**Dependencies:** `openpgp-card` (client library for the OpenPGP card
protocol) + `card-backend-pcsc` (PC/SC transport). This makes `pcscd` a
real new system dependency on Linux — stated plainly, not glossed over,
matching this ecosystem's existing "Honest tradeoffs" convention.
`aivyx-yubi` targets the card's **Signature key slot** specifically
(OpenPGP cards expose three independent key slots — Signature,
Decryption, Authentication, each with its own algorithm and touch-policy
— only Signature is relevant here, generated as Ed25519/EdDSA).

**What `aivyx-yubi` owns:** card discovery (enumerate connected
OpenPGP-capable devices), on-card Ed25519 key generation for the
Signature slot, touch-policy configuration, PIN-gated signing of an
arbitrary byte message, and reading back the public key + card
serial/AID for binding. It does not know anything about Aivyx's
federation protocol, instance ids, or request envelopes — that logic
stays in `aivyx-federation`. Same layering discipline as the other
extraction repos: a narrow, protocol-focused crate underneath,
product-specific logic on top.

## Provisioning flow

`aivyx-yubi` drives on-card key generation directly, surfaced to the
operator as a new subcommand in `aivyx`, e.g.
`aivyx federation yubikey-init`:

1. **Discover** connected OpenPGP-capable devices via `card-backend-pcsc`;
   no card found (or `pcscd` not running) fails with a clear, actionable
   error rather than a raw PC/SC error string.
2. **Refuse a factory-default PIN.** OpenPGP cards ship with well-known
   default PINs (`123456` user / `12345678` admin). `aivyx-yubi` checks
   for the default PIN as part of provisioning and refuses to proceed
   until the operator sets a real one via the standard OpenPGP-card
   PIN-change APDU (not by shelling out to `gpg`/`ykman`) — a real
   security-hygiene gap this project won't silently create.
3. **Generate the Signature-slot keypair on-card** (Ed25519/EdDSA) — the
   key is created inside the device; its private component never leaves
   it. `aivyx-yubi` only ever reads back the public key.
4. **Set the Signature slot's touch-policy to "fixed"/always-on"** — a
   one-time, permanent-until-reset card setting, not something
   `aivyx-federation` re-asserts per signature.
5. **Return the public key + the card's serial/AID.** `aivyx-federation`
   persists a small, non-secret binding record —
   `{instance_id, card_serial, public_key_base64}` — so it knows which
   physical card this identity expects, and can give a clear "wrong
   YubiKey inserted" error rather than a cryptic APDU failure if a
   different card shows up later. This record needs no encryption (no
   secret in it — the private key never touches disk at all on this
   path), so it doesn't need `aivyx-crypto`'s master-key-sealing
   machinery the software identity path uses.

## Integration into `aivyx-federation`

`Identity`'s public API (`sign_request`, `public_key_base64`,
`instance_id`, `verify_request`) stays stable — `verify_request` is
completely unaffected either way, since verification only ever needs the
public key, and a hardware-backed signature is bit-for-bit the same
64-byte Ed25519 signature format the software path already produces.
What changes is what's behind `Identity`: today it holds a concrete
`signing_key: SigningKey` field; this becomes an internal enum:

```rust
enum IdentitySigner {
    Software(SigningKey),
    Hardware(aivyx_yubi::YubiKeySigner),
}
```

`Identity::load_or_generate` (software) gets a sibling
`Identity::load_hardware(instance_id, binding_record)` (hardware)
constructor. `save_sealed`'s encrypted-key-file machinery is skipped
entirely on the hardware path.

**API-breaking change, deliberate, not incidental:** `sign_request` is
synchronous today (`fn sign_request(&self, body: &[u8]) -> SignedHeader`).
A touch-required hardware signature can legitimately block for several
seconds waiting on a physical tap — calling that synchronously from
inside `aivyx-channel`'s async daemon would stall a Tokio worker thread.
`Identity::sign_request` becomes `async fn`, returning
`Result<SignedHeader, FederationError>` (a new error case is added for
"card absent" and "touch timeout" — see below). Every existing call site
is already inside `aivyx-channel`'s async context, so this is a
mechanical `.await` addition at each site, not a structural rework of
the callers.

## Error handling & operational behavior

No silent fallback to a software key at any point — if hardware mode is
configured for an instance, a card problem is always a hard, clear
failure on that specific federation request, never a silent downgrade to
a weaker guarantee:

- **Card absent when a signature is needed** →
  `FederationError::Identity("YubiKey not detected — insert the card
  bound to this identity (serial {..}) and retry")`. The federation
  request that triggered signing simply fails; nothing queues or retries
  automatically.
- **Wrong card inserted** (serial doesn't match the persisted binding
  record) → a distinct, equally clear error naming both the expected and
  the found serial.
- **Touch not provided within the card's own timeout** → surfaces as a
  signing failure telling the operator to retry and physically tap the
  key. The OpenPGP card's own touch-timeout is a fixed device behavior,
  not something `aivyx-yubi` reimplements — it maps the resulting APDU
  error to a clear `FederationError`.
- **PIN needed but not cached / wrong PIN** → similarly explicit;
  `aivyx-yubi` never silently retries a PIN (no lockout-inducing retry
  loops) and never logs PIN attempts.

## Testing strategy

No real YubiKey/PC/SC hardware is available in this environment, so:

- `aivyx-yubi`'s card-protocol logic (APDU construction, response
  parsing, error mapping) is unit-tested against a fake
  `CardBackend`/`CardTransaction` implementation (the seam
  `openpgp-card` itself defines for a real vs. fake transport) —
  fabricated APDU responses standing in for a real card's replies.
- `aivyx-federation`'s `IdentitySigner::Hardware` path is tested against
  a fake `aivyx-yubi` signer (a trait object or test-only
  implementation), proving the async plumbing, the binding-record check,
  and each error mapping — without needing `aivyx-yubi`'s own real card
  logic to run.
- **Accepted, documented gap**: no test in this environment can exercise
  a real physical touch, a real PIN prompt, or real on-card key
  generation against actual hardware. Manual verification against a real
  YubiKey is a follow-up, not a merge blocker.
