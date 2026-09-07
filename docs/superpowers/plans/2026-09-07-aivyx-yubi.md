# aivyx-yubi Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `aivyx-yubi`, a standalone crate wrapping a YubiKey's
OpenPGP card applet for hardware-backed Ed25519 signing, then wire it
into `aivyx-federation`'s `Identity` as a new, purely additive/opt-in
signing backend, surfaced through a brand-new `aivyx federation
yubikey-init` CLI subcommand (the first production consumer
`aivyx-federation` has ever had).

**Architecture:** `aivyx-yubi` owns card discovery, on-card Ed25519 key
generation for the Signature slot, touch-policy configuration, PIN
handling, and raw-byte-message signing — no knowledge of Aivyx's
federation protocol. `aivyx-federation`'s `Identity` gains an internal
`IdentitySigner` enum (`Software`/`Hardware`) and `sign_request` becomes
`async fn` to accommodate a touch-required hardware signature blocking
for several seconds. Design spec:
`docs/superpowers/specs/2026-09-07-aivyx-yubi-design.md` (this repo,
including a correction made during this plan's own grounding pass — read
it in full before starting).

**Tech Stack:** Rust, `openpgp-card` (client library for the OpenPGP
card protocol) + `card-backend-pcsc` (PC/SC transport), `ed25519-dalek`
2.x (already workspace-pinned in `aivyx`), `thiserror`, `tokio`.

## Global Constraints

- OpenPGP applet only, not PIV — confirmed during design: the `yubikey`
  PIV crate is unmaintained since August 2023 and doesn't support
  Ed25519; `openpgp-card` is actively maintained and has supported
  Ed25519 since firmware 5.2.3 (2019). Do not introduce a PIV code path.
- Targets the card's **Signature key slot** specifically, not
  Authentication or Decryption.
- Touch-policy for the Signature slot is set to **fixed/always-on**
  during provisioning — every signature requires a physical touch, no
  PIN-only/cached mode. This is a one-time card setting, not re-asserted
  per signature.
- Provisioning **refuses a factory-default PIN** (`123456` user /
  `12345678` admin) — must fail loudly and require the operator to set a
  real PIN before proceeding, never silently generate a key behind a
  guessable PIN.
- Purely additive/opt-in: the existing software-generated `Identity`
  path (`Identity::generate`, `Identity::load_or_generate`,
  `save_sealed`) must be completely unmodified in behavior. Every
  existing test in `aivyx-federation` must still pass (updated only
  where `sign_request` becoming async requires a mechanical `.await`
  addition — no behavioral change).
- No silent fallback from hardware to software signing, ever. A card
  problem (absent, wrong card, touch timeout, PIN failure) is always a
  hard, clear, actionable error on that specific request.
- `pcscd` is a new system runtime dependency on Linux for anyone using
  hardware mode — document this plainly (`aivyx-yubi`'s own README, and
  wherever `aivyx`'s docs describe the new subcommand), never gloss over
  it.
- No test in this plan may require real YubiKey/PC/SC hardware — this
  environment has none. Use a fake implementation of `openpgp-card`'s
  own `CardBackend`/`CardTransaction` traits (the seam that crate itself
  defines for a real vs. fake transport) for every test that would
  otherwise need a real card.
- `aivyx-yubi` returns raw 64-byte Ed25519 signatures — no dependency on
  `ed25519-dalek` types is required in `aivyx-yubi` itself; the contract
  with `aivyx-federation` is "sign this byte slice, return 64 raw
  signature bytes, or a clear error."
- Repo scope: Tasks 1–6 live entirely in this repo (`aivyx-yubi`). Tasks
  7–8 live in `/home/julian/Projects/Rust/aivyx` (a **different git
  repo** — branch there, don't touch this repo's history). Each repo
  gets its own branch and its own `finishing-a-development-branch` pass
  at the end.
- The real `openpgp-card` crate's exact API (its typestate model —
  `Card<Open>` → `Card<Transaction>` → `Card<User>`/`Card<Admin>`/
  `Card<Sign>`, `OptionalPin`, and its exact method names) could not be
  fully confirmed from documentation alone during planning — docs.rs's
  rendered page did not expose complete method signatures. **Tasks 3, 4,
  and 5 must ground the real API by reading the actual vendored source**
  (`~/.cargo/registry/src/index.crates.io-*/openpgp-card-<version>/src/`,
  available after Task 1's `cargo build` first resolves it) before
  writing any code that calls it — the same discipline this project's
  own prior work used for `mistralrs`'s real vendored source rather than
  approximated docs. Do not guess at method names from the docs.rs
  summary alone.

---

## Part A — `aivyx-yubi` (this repo)

### Task 1: Cargo scaffold + dependency resolution check

**Files:**
- Create: `Cargo.toml`
- Create: `src/lib.rs`
- Create: `CLAUDE.md`
- Create: `README.md` (stub — full docs land in Task 6)

**Interfaces:**
- Produces: a crate that builds cleanly with `openpgp-card` and
  `card-backend-pcsc` as real, resolved dependencies — proving the
  version pins are valid before any real code is written on top of them
  (catches a bad pin or yanked version early and cheaply, mirroring the
  `aivyx-broker` plan's own Task 1 precedent).

- [ ] **Step 1: Write `Cargo.toml`**

```toml
[package]
name = "aivyx-yubi"
description = "Hardware-backed Ed25519 signing via a YubiKey's OpenPGP card applet"
version = "0.1.0"
edition = "2024"
license = "MIT OR Apache-2.0"

[dependencies]
openpgp-card = "0.7"
card-backend-pcsc = "0.5"
thiserror = "2"
tracing = "0.1.44"

[dev-dependencies]
```

(Leave `[dev-dependencies]` empty in this step — Task 2 adds the fake
card-backend test double as an in-crate module, not an external
dev-dependency, so nothing needs to go here yet. If `cargo add
card-backend-pcsc` resolves a different real version than `0.5` when you
run Step 2 below, use whatever version it actually resolves to — the
exact patch version isn't load-bearing, only that it resolves at all.)

- [ ] **Step 2: Write a minimal `src/lib.rs`** — just enough to prove the
  dependencies compile together

```rust
//! `aivyx-yubi` — hardware-backed Ed25519 signing via a YubiKey's
//! OpenPGP card applet. See `docs/superpowers/specs/
//! 2026-09-07-aivyx-yubi-design.md` for the full design rationale.

pub use openpgp_card::Card;
```

- [ ] **Step 3: `cargo build`**

Run: `cargo build`
Expected: builds clean. If `openpgp-card` or `card-backend-pcsc` fail to
resolve or a version conflict appears, fix the version pin in
`Cargo.toml` before proceeding to any later task.

- [ ] **Step 4: Write `CLAUDE.md`**

```markdown
# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`aivyx-yubi` wraps a YubiKey's OpenPGP card applet for hardware-backed
Ed25519 signing — card discovery, on-card key generation for the
Signature slot, touch-policy configuration, PIN handling, and raw-byte
signing. It has no knowledge of Aivyx's federation protocol or any
other product-specific concept; `aivyx-federation`'s `Identity` is its
first (and so far only) consumer.

See `docs/superpowers/specs/2026-09-07-aivyx-yubi-design.md` for the
full design rationale, including why the OpenPGP applet was chosen over
PIV (the `yubikey` PIV crate is unmaintained and lacks Ed25519 support;
`openpgp-card` is actively maintained and has supported Ed25519 since
firmware 5.2.3).

## Build, run, test, lint

\`\`\`sh
cargo build
cargo test
cargo clippy --all-targets
\`\`\`

**Requires `pcscd` running** to talk to a real card — a new system
dependency this crate introduces (not required by any other Aivyx
repo). Every test in this crate's own suite runs against a fake
`CardBackend`/`CardTransaction` implementation, not real hardware — this
environment has none. Manual verification against a real YubiKey is a
documented follow-up, not something this crate's own CI/tests can prove.

## Where to look next

- `README.md` — setup and usage.
- `docs/superpowers/specs/2026-09-07-aivyx-yubi-design.md` — full design.
```

- [ ] **Step 5: Write `README.md` stub**

```markdown
# aivyx-yubi

Hardware-backed Ed25519 signing via a YubiKey's OpenPGP card applet.
Full documentation lands once the implementation is complete (see
`docs/superpowers/plans/2026-09-07-aivyx-yubi.md`).
```

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml src/ CLAUDE.md README.md
git commit -m "feat: scaffold aivyx-yubi crate, resolve openpgp-card + card-backend-pcsc"
```

---

### Task 2: Ground the real `openpgp-card` API + build the fake card-backend test double

This task exists specifically because Task 1's dependency resolution
doesn't tell you the real API shape — every later task needs a fake
`CardBackend`/`CardTransaction` to test against, and every later task
needs the real `openpgp-card` type names grounded from source, so both
happen once, here, rather than being re-derived per task.

**Files:**
- Create: `src/testing.rs` (the fake card backend, `#[cfg(test)]`-only
  or behind a `test-util` feature — your call based on what you find;
  a `test-util` Cargo feature is the more reusable shape if later tasks'
  own test modules need to import it across files, which they will)
- Modify: `Cargo.toml` (add the feature if you go that route)

**Interfaces:**
- Consumes: nothing from earlier tasks beyond the crate scaffold.
- Produces: a fake implementation of `openpgp_card::card_backend::
  CardBackend` and `CardTransaction` (or whatever the real trait names
  turn out to be once grounded — see the note below) that Tasks 3, 4,
  and 5 all import for their own tests. Document in this file's own doc
  comment exactly which real trait(s) it implements and where you found
  them, since later task implementers will read this file to understand
  the seam.

- [ ] **Step 1: Ground the real API**

Read the real vendored source directly:
```bash
find ~/.cargo/registry/src -maxdepth 1 -iname "*openpgp-card*"
```
Then read that directory's `src/lib.rs` and whatever module defines
`CardBackend`/`CardTransaction` (search for `trait CardBackend`, `trait
CardTransaction` — these may live in a separate `card-backend` crate
that `openpgp-card` re-exports or depends on; check `Cargo.toml` inside
the vendored source to find out). Also read the typestate module (search
for `pub struct Open`, `pub struct Transaction`, `pub struct User`,
`pub struct Admin`, `pub struct Sign` or similar) to understand the real
state-transition API for opening a card, entering a transaction,
verifying a PIN, and switching into an admin/signing context. Take real
notes in this file's own doc comment — later tasks depend on this
grounding being accurate, not on you having gotten it approximately
right from docs.rs.

- [ ] **Step 2: Implement the fake backend**

Shape it to return pre-programmed APDU responses (fabricated card
replies) rather than talking to real hardware — the exact structure
depends on what Step 1 found, but at minimum it needs to support: a
fake serial/AID response (for Task 3's discovery test), a fake "PIN is
still factory default" vs. "PIN has been changed" response (Task 3), a
fake successful key-generation response with a fabricated public key
(Task 4), a fake touch-policy-set acknowledgment (Task 4), and a fake
signature response — plus fake *failure* responses for each (card
absent/unreachable, wrong PIN, touch timeout) so Task 5's error-mapping
tests have something real to assert against.

- [ ] **Step 3: Write a smoke test proving the fake backend itself works**

A minimal test that opens the fake backend, drives it through whatever
the real state-transition sequence is (per Step 1's grounding), and gets
back a fabricated response — proving the fake is wired correctly before
any real `aivyx-yubi` logic depends on it.

- [ ] **Step 4: `cargo test`, `cargo clippy --all-targets`, commit**

```bash
git add src/testing.rs Cargo.toml
git commit -m "test: ground real openpgp-card API, add fake card-backend test double"
```

---

### Task 3: Card discovery, serial/AID reading, PIN default-check

**Files:**
- Create: `src/discovery.rs`
- Create: `src/pin.rs`
- Modify: `src/lib.rs` (add modules, public error type)

**Interfaces:**
- Consumes: the fake `CardBackend`/`CardTransaction` from Task 2's
  `testing.rs` for tests; the real `card-backend-pcsc` crate for the
  real discovery path.
- Produces:
  - `pub fn discover_real_card() -> Result<Card<...>, YubiError>` (or
    whatever the real return type is once Task 2's grounding pins it
    down) — wraps `card-backend-pcsc`'s real PC/SC enumeration, mapping
    "no reader found"/"pcscd unreachable" to a clear `YubiError`
    variant naming the likely cause (pcscd not running) rather than a
    raw PC/SC error string.
  - `pub fn read_serial<...>(card: &mut Card<...>) -> Result<String, YubiError>`
    — the card's serial/AID, needed by `aivyx-federation`'s binding
    record (Task 7) so it can detect "wrong card inserted."
  - `pub fn is_pin_factory_default<...>(card: &mut Card<...>) -> Result<bool, YubiError>`
    and `pub fn require_pin_changed<...>(card: &mut Card<...>) -> Result<(), YubiError>`
    (the latter calling the former and returning a clear,
    provisioning-blocking error if the PIN is still `123456`/`12345678`
    — per this plan's Global Constraints, provisioning must refuse to
    proceed on a factory-default PIN).
  - `pub enum YubiError { CardNotFound(String), PinStillFactoryDefault, WrongCard { expected: String, found: String }, TouchTimeout, PinIncorrect, Other(String) }`
    (adjust variants based on what Tasks 4/5 also need — this is the
    error type every later task's public functions return).

- [ ] **Step 1: Write the failing tests** (against Task 2's fake
  backend — a card reporting a fabricated serial, a card reporting the
  factory-default PIN, a card reporting a changed PIN, "no card found"
  against an empty fake reader list)

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p aivyx-yubi discovery pin`
Expected: compile errors (functions don't exist yet).

- [ ] **Step 3: Implement `discovery.rs` and `pin.rs`** against the real
  grounded API from Task 2.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p aivyx-yubi discovery pin`
Expected: all new tests pass.

- [ ] **Step 5: `cargo clippy --all-targets`, commit**

```bash
git add src/discovery.rs src/pin.rs src/lib.rs
git commit -m "feat: card discovery, serial reading, factory-default-PIN enforcement"
```

---

### Task 4: On-card Ed25519 key generation + touch-policy

**Files:**
- Create: `src/provision.rs`
- Modify: `src/lib.rs` (add module)

**Interfaces:**
- Consumes: `YubiError` (Task 3), the fake backend (Task 2), the real
  grounded typestate API (Task 2's notes).
- Produces: `pub fn generate_signature_key<...>(card: &mut Card<...>) -> Result<PublicKeyBytes, YubiError>`
  (generates an Ed25519 keypair on-card in the Signature slot, returns
  the raw 32-byte Ed25519 public key — define `pub struct PublicKeyBytes([u8; 32])`
  or just return `[u8; 32]` directly, whichever reads cleaner once you
  see the real API's own return shape) and
  `pub fn set_signature_touch_policy_fixed<...>(card: &mut Card<...>) -> Result<(), YubiError>`
  (sets the Signature slot's touch-policy to fixed/always-on — a
  one-time card setting per this plan's Global Constraints).

- [ ] **Step 1: Write the failing tests** against Task 2's fake backend
  (successful key generation returns a fabricated 32-byte public key;
  touch-policy-set succeeds; each also has a failure-path test — e.g.
  key generation attempted without PIN/admin auth first, mapped to a
  clear `YubiError`).

- [ ] **Step 2: Run to verify failure**

- [ ] **Step 3: Implement `provision.rs`** against the real grounded API.

- [ ] **Step 4: Run to verify pass**

- [ ] **Step 5: `cargo clippy --all-targets`, commit**

```bash
git add src/provision.rs src/lib.rs
git commit -m "feat: on-card Ed25519 key generation + fixed touch-policy for the Signature slot"
```

---

### Task 5: Signing operation + full error mapping

**Files:**
- Create: `src/sign.rs`
- Modify: `src/lib.rs` (public re-exports — this is the crate's main
  external API surface, so make sure everything Task 7
  (`aivyx-federation`) needs is actually `pub` from the crate root, not
  just from an internal module)

**Interfaces:**
- Consumes: everything from Tasks 2–4.
- Produces the crate's real external contract:
  ```rust
  pub struct YubiKeySigner { /* holds whatever the real Card<...> state needs to persist across signing calls */ }

  impl YubiKeySigner {
      pub fn public_key(&self) -> [u8; 32];
      pub fn card_serial(&self) -> &str;
      pub fn sign(&mut self, message: &[u8]) -> Result<[u8; 64], YubiError>;
  }
  ```
  (Exact shape — e.g. whether `sign` needs `&mut self` or takes the
  `Card` fresh each call — depends on what Task 2's grounding found
  about whether a `Card<Transaction>`/`Card<Sign>` handle can be held
  across calls or must be re-opened each time. If the real PC/SC/card
  session can't safely be held open indefinitely between signing calls
  — plausible, since the operator may unplug the key between uses —
  design `sign` to re-discover and re-open fresh each call rather than
  assuming a long-lived open handle; note this decision in `sign.rs`'s
  own doc comment either way, since Task 7 needs to know whether
  `YubiKeySigner` is safe to hold in `Identity` across the daemon's
  whole lifetime or must be reconstructed per signature.)

- [ ] **Step 1: Write the failing tests** against Task 2's fake backend:
  a successful sign returns a fabricated 64-byte signature; card absent
  maps to `YubiError::CardNotFound`; wrong PIN maps to
  `YubiError::PinIncorrect`; a simulated touch-timeout maps to
  `YubiError::TouchTimeout`. Also test `public_key()`/`card_serial()`
  against the fake's fabricated identity.

- [ ] **Step 2: Run to verify failure**

- [ ] **Step 3: Implement `sign.rs`** against the real grounded API,
  wiring the full flow: discover → verify PIN not needed (touch-only
  signing doesn't require PIN entry if `openpgp-card`'s own PIN caching
  behaves that way — or does, if the real API requires PIN verification
  before every `PSO:CDS` call regardless of touch-policy; ground this
  precisely from the real source in Task 2's notes rather than assuming
  either way) → sign → map every failure path to the right `YubiError`
  variant.

- [ ] **Step 4: Run to verify pass**

- [ ] **Step 5: `cargo clippy --all-targets`, commit**

```bash
git add src/sign.rs src/lib.rs
git commit -m "feat: YubiKeySigner -- PIN/touch-gated Ed25519 signing over arbitrary bytes"
```

---

### Task 6: README.md + CLAUDE.md finalization

**Files:**
- Modify: `README.md` (replace stub with full docs)
- Modify: `CLAUDE.md` (add a "Known limitations" section)

**Interfaces:** none — documentation only.

- [ ] **Step 1: Write the full `README.md`**

```markdown
# aivyx-yubi

Hardware-backed Ed25519 signing via a YubiKey's OpenPGP card applet —
built so `aivyx-federation`'s cross-boundary identity key can live in a
hardware device instead of (even encrypted) on disk, with every
signature requiring a physical touch.

## Why the OpenPGP applet, not PIV

Confirmed directly against the real crate ecosystem before choosing:
the `yubikey` Rust crate (PIV) hasn't been updated since August 2023 and
its own docs list no Ed25519 support, even though firmware 5.7+ (2024)
added it to PIV — the crate hasn't caught up. `openpgp-card` (this
crate's real dependency) is actively maintained and has supported
Ed25519 since firmware 5.2.3 (2019), covering far more YubiKeys already
in the wild. See `docs/superpowers/specs/2026-09-07-aivyx-yubi-design.md`
for the full account.

## Requirements

- A YubiKey (or other OpenPGP-card-compatible device) with firmware
  5.2.3 or later.
- **`pcscd` running** — this crate talks to the card over PC/SC via
  `card-backend-pcsc`, which needs the PC/SC daemon reachable. Install
  and enable it per your distro (`pcscd` on most Linux distros; macOS
  and Windows have PC/SC built into the OS).

## What this crate does (and doesn't)

- Discovers connected OpenPGP-card-compatible devices.
- Generates an Ed25519 keypair **on the card itself** for the Signature
  key slot — the private key never leaves the device.
- Sets the Signature slot's touch-policy to fixed/always-on: every
  signature requires a physical tap.
- Refuses to provision a key while the card's PIN is still the
  well-known factory default (`123456`).
- Signs arbitrary byte messages, returning a raw 64-byte Ed25519
  signature.
- Has **no knowledge of Aivyx's federation protocol** or any other
  product concept — `aivyx-federation`'s `Identity` is the consumer that
  gives this primitive meaning.

## Testing

No real YubiKey/PC/SC hardware is available in this crate's own CI —
every test runs against a fake `CardBackend`/`CardTransaction`
implementation (`src/testing.rs`). Manual verification against a real
device is a documented follow-up, not something this crate's own test
suite can prove.
```

- [ ] **Step 2: Add a "Known limitations" section to `CLAUDE.md`**

```markdown

## Known, deliberately-undefended limitations

- Requires `pcscd` — a real new system dependency for anyone using this
  crate, not required by any other Aivyx repo.
- No PIV support. OpenPGP-applet-only; revisit if the `yubikey` crate
  (or an alternative) catches up with firmware 5.7's PIV Ed25519
  support.
- No test in this crate's own suite exercises real hardware — a real
  physical touch, a real PIN prompt, or real on-card key generation
  against actual silicon. All tests run against a fake card backend.
```

- [ ] **Step 3: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: write full README and CLAUDE.md for aivyx-yubi"
```

---

## Part B — client integration in `aivyx`

**Repo:** `/home/julian/Projects/Rust/aivyx` — a separate git repo.
Branch before starting (see `superpowers:using-git-worktrees`); do not
commit to this repo's default branch directly.

### Task 7: `IdentitySigner` + async `sign_request` in `aivyx-federation`

**Files:**
- Modify: `crates/aivyx-federation/Cargo.toml` (add `aivyx-yubi` as a
  path or git dependency — this repo's own decision at merge time,
  matching how `aivyx-broker` depended on `aivyx-kvcache` via `git`;
  since both `aivyx-yubi` and `aivyx` are local-only right now with no
  GitHub remote, use a relative `path = "../../../aivyx-yubi"`-style
  dependency for now if `aivyx-yubi` has no remote yet at
  implementation time — check with `git -C
  /home/julian/Projects/Rust/aivyx-yubi remote -v` before deciding; a
  `path` dependency across sibling directories in this workspace layout
  is consistent with how this workspace already works day-to-day even
  though each repo is independently versioned)
- Modify: `crates/aivyx-federation/src/identity.rs` (the core of this
  task)
- Modify: `crates/aivyx-federation/src/relay.rs` (`sign_relay` becomes
  async too, since it calls `sign_request`)
- Modify: `crates/aivyx-federation/src/lib.rs` (new `FederationError`
  variants)

**Interfaces:**
- Consumes: `aivyx-yubi`'s real public API from Task 5
  (`YubiKeySigner::sign`/`public_key`/`card_serial`, `YubiError`) —
  ground the exact final shape fresh from that crate's own `src/sign.rs`
  and `src/lib.rs` before writing this task's code; the plan's own
  description of it above may have evolved during Tasks 2–5's own
  grounding.
- Produces: the stable `Identity` public API (`sign_request`,
  `public_key_base64`, `instance_id`, `verify_request` — unchanged
  signature except `sign_request`) that Task 8's CLI subcommand and any
  future consumer depend on.

- [ ] **Step 1: Ground the exact current state before editing**

Re-read `crates/aivyx-federation/src/identity.rs` and `relay.rs` in
full fresh (line numbers may have drifted since this plan was written).
Confirm `aivyx-yubi`'s real final API by reading its own `src/lib.rs`
and `src/sign.rs` fresh too.

- [ ] **Step 2: Add the new `FederationError` variants**

```rust
/// A hardware-backed signing operation failed (card absent, wrong card,
/// touch not provided, PIN rejected). Wraps `aivyx_yubi::YubiError`'s
/// own message rather than re-deriving a parallel taxonomy.
#[error("YubiKey signing error: {0}")]
Hardware(String),
```

(Add this as a new variant on the existing `FederationError` enum in
`lib.rs`, following its existing style exactly — don't restructure the
enum's other variants.)

- [ ] **Step 3: Introduce `IdentitySigner` and refactor `Identity`**

```rust
enum IdentitySigner {
    Software(SigningKey),
    Hardware(aivyx_yubi::YubiKeySigner),
}

impl IdentitySigner {
    fn public_key_bytes(&self) -> [u8; 32] {
        match self {
            IdentitySigner::Software(k) => k.verifying_key().to_bytes(),
            IdentitySigner::Hardware(h) => h.public_key(),
        }
    }
}
```

Change `Identity`'s field from `signing_key: SigningKey` to
`signer: IdentitySigner`, and `verifying_key: VerifyingKey` stays as-is
(constructed from `signer.public_key_bytes()` at `Identity` construction
time in both `new`/`generate` (software) and the new hardware
constructor below — `verifying_key` itself never needs to know which
backend produced the bytes, since `verify_request` already only deals in
raw public key bytes today).

Update the manual `Debug` impl: the `Hardware` variant should redact
just as thoroughly as `Software` does today (no card serial or PIN
state ever printed — `card_serial()` is not secret, but keep the same
conservative redaction posture this file already documents as a hard
requirement, FED.0 §7).

- [ ] **Step 4: Add the hardware constructor**

```rust
impl Identity {
    /// Build an `Identity` backed by a YubiKey's OpenPGP card applet
    /// instead of a software-generated key. `expected_serial` is the
    /// card serial this identity was originally provisioned against
    /// (persisted by whoever calls this — see `aivyx`'s
    /// `federation yubikey-init` CLI subcommand) — if the currently
    /// connected card's serial doesn't match, this fails loudly rather
    /// than silently trusting a different physical device.
    pub fn load_hardware(
        instance_id: String,
        signer: aivyx_yubi::YubiKeySigner,
        expected_serial: &str,
    ) -> Result<Self, FederationError> {
        validate_instance_id(&instance_id)?;
        if signer.card_serial() != expected_serial {
            return Err(FederationError::Hardware(format!(
                "wrong YubiKey inserted: expected card serial {expected_serial}, found {}",
                signer.card_serial()
            )));
        }
        let public_key_bytes = signer.public_key();
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|e| FederationError::Hardware(format!("invalid Ed25519 key from card: {e}")))?;
        Ok(Self {
            instance_id,
            signer: IdentitySigner::Hardware(signer),
            verifying_key,
        })
    }
}
```

(Adjust field names/types to match whatever Step 3 actually produced —
this is reference logic, not necessarily copy-paste-exact.)

- [ ] **Step 5: Make `sign_request` async and backend-dispatching**

```rust
/// Sign a request body, producing a `SignedHeader`. Async because the
/// hardware-backed path can legitimately block for several seconds
/// waiting on a physical touch -- callers must `.await` this even
/// though the software-backed path completes synchronously in
/// practice.
pub async fn sign_request(&mut self, body: &[u8]) -> Result<SignedHeader, FederationError> {
    let timestamp = now_secs();
    let body_hash = sha256_hex(body);
    let message = format!("{}:{}:{}", self.instance_id, timestamp, body_hash);
    let signature_bytes = match &mut self.signer {
        IdentitySigner::Software(k) => k.sign(message.as_bytes()).to_bytes(),
        IdentitySigner::Hardware(h) => h
            .sign(message.as_bytes())
            .map_err(|e| FederationError::Hardware(e.to_string()))?,
    };
    Ok(SignedHeader {
        instance_id: self.instance_id.clone(),
        timestamp,
        signature: BASE64.encode(signature_bytes),
    })
}
```

Note `&mut self` — `sign_request` was `&self` before; the hardware path
needs `&mut self` if Task 5's `YubiKeySigner::sign` needs `&mut self`
(ground this from the real `aivyx-yubi` API per Step 1, and adjust to
`&self` throughout if it turns out `sign` doesn't need mutability).
Whichever it is, keep `Identity`'s own method consistent with
`YubiKeySigner`'s real requirement rather than fighting it with
internal `Mutex`/`RefCell` wrapping.

- [ ] **Step 6: Update `relay.rs`'s `sign_relay`**

```rust
pub async fn sign_relay(
    &mut self,
    req: &RelayRequest,
) -> Result<(SignedHeader, Vec<u8>), FederationError> {
    let body = relay_body_bytes(req)?;
    let header = self.sign_request(&body).await?;
    Ok((header, body))
}
```

- [ ] **Step 7: Update every existing test to the new async signature**

Every test in `identity.rs` and `relay.rs` that calls `.sign_request(...)`
or `.sign_relay(...)` needs `#[tokio::test]` (instead of `#[test]`) and
an `.await` added at the call site. This is mechanical — confirmed by
this plan's own grounding that these are the *only* real call sites in
the entire workspace (no production code depends on the old sync
signature). Add `tokio = { workspace = true, features = ["macros",
"rt"] }` to `[dev-dependencies]` in `Cargo.toml` if it isn't already a
dev-dependency of this crate (check first — `aivyx-federation`'s current
`Cargo.toml` has no `tokio` dependency at all per this plan's own
grounding, so this is a genuinely new dev-dependency, not already
present).

- [ ] **Step 8: Write new tests for the hardware path**

Using a test-only fake `aivyx_yubi::YubiKeySigner`-shaped construction
(if `YubiKeySigner` itself can be constructed directly in test code with
fabricated key/serial values, do that; if `aivyx-yubi`'s real
`YubiKeySigner` can only be constructed via its own internal discovery
flow, this task needs its own small test-only trait/enum abstraction in
`aivyx-federation` instead — ground this from `aivyx-yubi`'s real Task 5
API and use whichever is actually possible). At minimum: a test proving
`load_hardware` rejects a mismatched card serial; a test proving a
successful hardware `sign_request` produces a `SignedHeader` that
verifies correctly via the existing `verify_request` (proving the
hardware path's signature format is identical to the software path's);
a test proving a hardware signing failure (`YubiError`) maps to
`FederationError::Hardware` and propagates as an `Err`, not a panic or
silent fallback to software signing.

- [ ] **Step 9: Run the full workspace suite and clippy**

Run: `cargo test --workspace --exclude aivyx-desktop && cargo clippy --workspace --exclude aivyx-desktop --all-targets -- -D warnings`
Expected: all tests pass (including every mechanically-updated existing
test), clippy clean.

- [ ] **Step 10: Commit**

```bash
git add crates/aivyx-federation/
git commit -m "feat: add IdentitySigner::Hardware, make sign_request async for YubiKey support"
```

---

### Task 8: `aivyx federation yubikey-init` CLI subcommand

**Files:**
- Create: `crates/aivyx-cli/src/bin/aivyx_modules/federation.rs`
- Modify: `crates/aivyx-cli/src/bin/aivyx.rs` (new `CliMode::Federation`
  variant + dispatch, following the exact hand-rolled pattern the
  existing `CliMode::Identity`/`CliMode::Access`/`CliMode::Autonomy`
  variants use — **do not** name anything in this new subcommand
  `identity`; `aivyx identity` is already a real, unrelated command
  (Persona/Profile export) — the new command is `aivyx federation
  yubikey-init`, never `aivyx identity ...`)
- Modify: `crates/aivyx-cli/Cargo.toml` (add `aivyx-federation` as a
  real dependency for the first time — confirmed by this plan's own
  grounding that no crate in the workspace depends on it today)
- Modify: `README.md` or `docs/FEDERATION.md` (whichever this repo's
  own convention points to for federation-related operator docs — check
  fresh which file currently documents `docs/FEDERATION.md`'s own
  existing content before deciding where the new subcommand's usage
  belongs)

**Interfaces:**
- Consumes: Task 7's `Identity::load_hardware`, and `aivyx-yubi`'s
  provisioning flow directly (`discover_real_card`, `require_pin_changed`,
  `generate_signature_key`, `set_signature_touch_policy_fixed` — ground
  the exact final names from `aivyx-yubi`'s real `src/lib.rs` fresh,
  since Tasks 2–5's own implementation may have settled on slightly
  different names than this plan's own working sketch).
- Produces: nothing consumed by a later task — last task in this plan.

- [ ] **Step 1: Ground the exact current state before editing**

Re-read `aivyx.rs`'s `CliMode` enum, the `CliMode::Identity` dispatch
arm (as the closest structural precedent — a subcommand that talks to
the daemon and/or does local file work), and `aivyx_modules/identity.rs`
in full (as the file-structure precedent to mirror, even though the
command name itself must differ) fresh before writing code — line
numbers in this plan are not authoritative.

- [ ] **Step 2: Write `aivyx_modules/federation.rs`**

Implements `pub async fn run_yubikey_init(instance_id: &str, key_binding_path: &Path) -> Result<(), String>`
(or whatever shape matches this file's sibling modules' own established
return-type convention — check `identity.rs`'s `run_identity_export`
signature as the precedent) driving the full provisioning flow from the
design spec's "Provisioning flow" section: discover the real card →
`require_pin_changed` (surfacing a clear "change your PIN first, here's
how" error if it's still factory-default, per this plan's Global
Constraints — do not attempt to change the PIN on the operator's behalf
here, only refuse to proceed) → generate the Signature-slot Ed25519
keypair → set touch-policy fixed → construct the binding record
(`{instance_id, card_serial, public_key_base64}`) → write it to
`key_binding_path` as plain (non-secret, per the design) JSON.

- [ ] **Step 3: Wire the CLI dispatch in `aivyx.rs`**

Add `CliMode::Federation(FederationSubcommand)` (or whatever enum
structure matches the file's existing convention for a subcommand with
sub-subcommands — `CliMode::Identity(IdentitySubcommand)` is the direct
precedent to mirror), parsing `aivyx federation yubikey-init` from the
raw args the same way `"identity export"` is parsed today (string
matching against `args`, per this file's own established, non-clap-derive
convention).

- [ ] **Step 4: Write tests**

Mirror however `aivyx.rs`'s own existing CLI-arg-parsing tests for
`identity export`/`identity import` are structured (search near line
13630+ per this plan's own earlier grounding, though line numbers will
have drifted) — a test that `federation yubikey-init` parses correctly,
a test that a missing/malformed invocation produces a clear usage error.
Since this task's core logic (the provisioning flow itself) needs real
or fake hardware to exercise meaningfully, and this environment has
neither, the CLI-layer tests here should focus on argument parsing and
dispatch, not re-testing `aivyx-yubi`'s own already-tested card logic —
that would just be re-testing Tasks 2–5's work through an extra layer
for no new coverage.

- [ ] **Step 5: Update docs**

Add the new subcommand to whichever file documents `aivyx`'s CLI surface
(check `docs/FEDERATION.md` and/or the main `README.md`'s command
reference — mirror however `aivyx identity export` or similarly-scoped
commands are already documented there), including the `pcscd`
requirement stated plainly (per this plan's Global Constraints — don't
bury or omit it).

- [ ] **Step 6: Run the full workspace suite and clippy**

Run: `cargo test --workspace --exclude aivyx-desktop && cargo clippy --workspace --exclude aivyx-desktop --all-targets -- -D warnings`

- [ ] **Step 7: Commit**

```bash
git add crates/aivyx-cli/ docs/ README.md
git commit -m "feat: add aivyx federation yubikey-init CLI subcommand"
```

---

## After all tasks

Each of the two repos gets its own `finishing-a-development-branch` pass
— independent histories, independent merges. Update
`aivyx-ecosystem/ROADMAP.md` with one cross-repo entry once both are
merged, following this session's established pattern (see the
`aivyx-broker` project's own roadmap entry for the shape to match) —
this is a controller-driven post-merge documentation step, not one of
the numbered tasks above.
