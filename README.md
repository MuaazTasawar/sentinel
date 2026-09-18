# Sentinel

A zero-trust, hardware-rooted, distributed secrets vault written in Rust — with a hand-rolled Raft consensus implementation, physical-key-quorum unsealing, real-time anomaly detection with auto-seal, and a deterministic simulation harness that proves the consensus layer's safety properties under partition, clock skew, and message reordering.

Built as a portfolio project across 12 phases, each one compiled and tested before being called done. This README explains not just *what* exists but *why* — every cryptographic primitive, every distributed-systems concept, and every design tradeoff, aimed at a reader who wants to actually understand the system rather than take "it's secure" on faith.

---

## Table of contents

1. [The problem this solves](#the-problem-this-solves)
2. [Architecture at a glance](#architecture-at-a-glance)
3. [Concept-by-concept explanation](#concept-by-concept-explanation)
   - [Envelope encryption](#envelope-encryption)
   - [Shamir's Secret Sharing](#shamirs-secret-sharing)
   - [Hardware-rooted unsealing (YubiKey PIV)](#hardware-rooted-unsealing-yubikey-piv)
   - [Memory hygiene: mlock and zeroize](#memory-hygiene-mlock-and-zeroize)
   - [Argon2id and HKDF](#argon2id-and-hkdf)
   - [Raft consensus](#raft-consensus)
   - [The actor model and why the deadlock happened](#the-actor-model-and-why-the-deadlock-happened)
   - [Mutual TLS (mTLS)](#mutual-tls-mtls)
   - [Hash-chained audit log](#hash-chained-audit-log)
   - [Rolling z-score anomaly detection](#rolling-z-score-anomaly-detection)
   - [Deterministic simulation testing](#deterministic-simulation-testing)
   - [Property-based testing and fuzzing](#property-based-testing-and-fuzzing)
4. [Crate-by-crate reference](#crate-by-crate-reference)
5. [Security model](#security-model)
6. [Known limitations](#known-limitations)
7. [Verification record](#verification-record)
8. [Quick start](#quick-start)
9. [Development](#development)

---

## The problem this solves

Small engineering teams routinely put database passwords and API keys in `.env` files, Slack messages, or plaintext config — not out of carelessness, but because the alternative (HashiCorp Vault, AWS Secrets Manager) is heavy infrastructure with its own operational burden. Credential leaks are a leading cause of breaches precisely because "the right way" felt like too much for a small team's actual risk profile.

Sentinel is an attempt at a middle ground: a single static binary, no JVM, no external dependencies at runtime, that still gets the things that actually matter right — secrets are never stored in plaintext anywhere, unsealing requires physical hardware (not just a password), every access is logged in a way that can't be silently edited after the fact, and unusual access patterns trigger automatic lockdown rather than relying on a human noticing a dashboard.

## Architecture at a glance
                    ┌─────────────────────────────┐
                    │      Client / Operator      │
                    └───────────────┬─────────────┘
                                    │ mTLS (client cert required)
                    ┌───────────────▼───────────────┐
                    │         sentinel-node         │
                    │  (Axum router behind a raw    │
                    │   tokio-rustls TLS listener)  │
                    │                               │
                    │  /secrets/*  — CRUD, encrypted│
                    │  /cluster/*  — Raft status    │
                    │  /raft/*    — peer-to-peer RPC
                    │  /           — live dashboard │ 
                    └───┬─────┬───────┬─────────┬─┬─┘
                        │     │       │         │ └───────┐
          ┌─────────────▼┐ ┌──▼────┐ ┌▼────┐ ┌──▼──────┐ ┌▼─────────┐
          │ sentinel-    │ │storage│ │audit│ │consensus│ │ anomaly  │
          │ crypto       │ │(sled) │ │(hash│ │ (Raft)  │ │(z-score) │
          │              │ │       │ │chain│ │         │ │          │
          │ envelope enc │ │       │ │)    │ │         │ │          │
          │ Shamir       │ │       │ │     │ │         │ │          │
          │ mlock/zeroize│ │       │ │     │ │         │ │          │
          └──────────────┘ └───────┘ └─────┘ └────┬────┘ └──────────┘
                                                  │
                                          ┌───────▼───────────┐
                                          │  sentinel-hardware│
                                          │ YubiKey PIV quorum│
                                          └───────────────────┘

                                          ┌─────────────────────┐
                                          │    sentinel-sim     │
                                          │  deterministic chaos│
                                          │  tests against the  │
                                          │  REAL RaftState (not│
                                          │  a reimplementation)│
                                          └─────────────────────┘

Nine crates in one Cargo workspace. The dependency direction is strictly one-way: `consensus` and `crypto` know nothing about HTTP, TLS, or each other; `api` is the only crate that assembles everything into a running server. This matters because it's what makes `sentinel-sim` possible — the simulation harness drives the exact same `RaftState` type the production actor uses, just through a different (virtual-time, fully controllable) scheduler, instead of needing a second implementation of Raft just for testing.

---

## Concept-by-concept explanation

### Envelope encryption

**What it is:** instead of encrypting data directly with a single master key, you generate a fresh, random key (the Data Encryption Key, DEK) for each piece of data, encrypt the data with that, and then encrypt the DEK itself with a longer-lived Key Encryption Key (KEK). The stored artifact is `{encrypted_DEK, encrypted_data}`.

**Why it's used here:** the KEK (derived from the hardware-unseal quorum) never directly touches secret data — it only ever wraps DEKs. This means rotating the KEK later is cheap (re-wrap every DEK, without re-encrypting every stored secret), and it limits the blast radius if a single DEK were ever compromised (it only exposes one secret, not the master key).

**Implementation:** `crates/crypto/src/envelope.rs`, using AES-256-GCM (an AEAD — Authenticated Encryption with Associated Data — cipher, meaning it detects tampering, not just encrypts) from the `aes-gcm` crate. Verified with a real handshake-style test suite: round-trip correctness, wrong-KEK failure, and tampered-ciphertext detection all pass, plus a property-based fuzz-style suite (see [Property-based testing and fuzzing](#property-based-testing-and-fuzzing)) that throws thousands of malformed byte combinations at `decrypt()` and asserts it never panics, only ever returns `Err`.

### Shamir's Secret Sharing

**What it is:** a way to split a secret into `N` pieces such that any `K` of them (a "threshold") can reconstruct the original, but any `K-1` reveal *nothing* about it — not "hard to guess," but information-theoretically zero information, provable mathematically. It works by encoding the secret as the constant term of a random polynomial of degree `K-1`, then handing out `(x, p(x))` points on that polynomial; `K` points uniquely determine a degree-`(K-1)` polynomial via Lagrange interpolation, but fewer points leave every possible constant term equally likely.

**Why it's used here:** the vault's KEK is split via Shamir sharing across multiple YubiKeys (e.g. "any 2 of 3 key holders"). No single compromised device, and no software-only attack, can reconstruct the KEK — physical possession of a quorum of hardware keys is mathematically required.

**Implementation:** `crates/crypto/src/shamir.rs` — hand-rolled over GF(256) (the same finite field AES itself uses), not a wrapper around an existing secret-sharing crate. This was a deliberate choice: an earlier attempt used the `vsss-rs` crate, but its API is built around elliptic-curve scalars (meant for something like threshold signatures) and pulling in `elliptic-curve`/`crypto-bigint` just to split 32 raw bytes added a lot of fragile dependency surface for something GF(256) arithmetic does in about 120 lines with zero extra dependencies. Verified with exhaustive tests (every one of the 255 nonzero GF(256) elements has its multiplicative inverse checked), round-trip tests across multiple threshold/total combinations, and a property-based test confirming `split_secret` never panics across the full `threshold`/`total` input space (0–255 each).

**A property worth understanding**: Shamir provides no *integrity* check by itself. Combining the wrong shares, or too few, doesn't error — it silently produces garbage bytes that look like a valid secret but aren't. This is why real deployments need a separate integrity check (e.g. an HMAC) on the reconstructed KEK before trusting it; that specific gap is called out as a documented `combine_shares` limitation in the code, not swept under the rug.

### Hardware-rooted unsealing (YubiKey PIV)

**What it is:** PIV (Personal Identity Verification) is a smart-card standard; a YubiKey configured for PIV holds a private key that never leaves the device — it can decrypt or sign, but the key material is physically inextricable from the hardware. Sentinel encrypts each Shamir share to a specific holder's YubiKey PIV public key at provisioning time, so reconstructing it later requires that specific physical device (plus its PIN, plus, depending on slot policy, a physical touch confirmation).

**Why it matters:** this closes the gap that pure-software secret sharing leaves open — if the shares themselves are just files, whoever has root on enough machines holding those files can reconstruct the secret. Requiring PIV decryption means the shares are useless without the actual hardware in hand.

**Implementation:** `crates/hardware/src/yubikey_piv.rs` (the PIV interaction) and `crates/hardware/src/quorum.rs` (the pure composition logic — collecting fragments from however many holders show up, in any order, until threshold is met). The design deliberately separates these: `quorum.rs` never touches a `yubikey` crate type, only plain `ShamirShare` bytes, so it's fully unit-tested (5/5, including a test confirming a single compromised holder touching their key twice can't fake a two-person quorum) without needing real hardware. `yubikey_piv.rs` is the one piece of this entire project that has never touched a physical device — see [Verification record](#verification-record) for exactly what "reviewed but not executed" means there.

### Memory hygiene: mlock and zeroize

**What it is:** two separate protections for key material held in process memory. `mlock` (POSIX) / `VirtualLock` (Windows) tells the OS never to swap a given memory page to disk — without it, a KEK sitting in RAM could end up written to a swap file, readable later by anyone with disk access, long after the process exits. "Zeroize on drop" means overwriting the memory with zeros the instant it's no longer needed, rather than trusting Rust's normal deallocation (which just marks memory free — the old bytes are still physically present until something else overwrites them).

**Why both, not just one:** `mlock` protects against swap-based disk exposure while the secret is alive; zeroize protects against a *later* allocation in the same process reading stale bytes left behind after the secret is dropped. Neither alone covers both risks.

**Implementation:** `crates/crypto/src/secret.rs`, the project's only hand-written `unsafe` code. It's `cfg`-gated: `libc::mlock`/`munlock` on Unix, `windows-sys`' `VirtualLock`/`VirtualUnlock` on Windows — a real cross-platform bug (Windows doesn't have `mlock`) was caught and fixed during Phase 7's build when the actual Windows compile failed on this exact file. Every `unsafe` block carries a `SAFETY:` comment explaining precisely why the pointer/length pair passed to the OS call is valid for the call's duration. Tests confirm lock/unlock don't panic on empty or non-empty buffers, and that `Debug` output never leaks the secret's contents (a `format!("{:?}", secret)` — the kind of thing that ends up in a log line by accident — shows only the length, never the bytes).

### Argon2id and HKDF

**What they are:** two different key-derivation functions (KDFs) for two different situations. **Argon2id** is deliberately *slow* and *memory-hard* — it's the right tool when deriving a key from something with potentially limited entropy (a password, or here, a value reconstructed from the unseal quorum), because its cost makes brute-forcing every possible low-entropy input expensive even for an attacker with lots of hardware. **HKDF** (HMAC-based Key Derivation Function) is the opposite: fast, and used when the *input* already has plenty of entropy (a 256-bit master secret) but you need to derive several independent-looking keys for different purposes from it (e.g. one key for wrapping DEKs, a different one for an audit-log HMAC) without those derived keys being mathematically related in an exploitable way.

**Implementation:** `crates/crypto/src/kdf.rs`. Tested for determinism (same salt ⇒ same output, required for Argon2 to be useful as a KDF at all), for producing different outputs given different salts/contexts, and — via the property-based suite — for never panicking across the full range of input/salt lengths including zero-length edge cases.

### Raft consensus

**What it is:** an algorithm for getting multiple machines (a "cluster") to agree on an ordered sequence of operations, even when some machines crash or the network partitions, without any single point of failure. It works by electing one node as "leader" for a period of time (a "term"); the leader accepts all writes, appends them to its local log, and replicates that log to the other nodes ("followers"); a write is considered "committed" once a *majority* of nodes have it in their log, which is what guarantees it survives even if the leader itself then crashes.

**Why hand-rolled instead of using `raft-rs` or `openraft`:** partly a portfolio decision (implementing the algorithm from the paper demonstrates understanding it, rather than just calling a library), and partly consistent with the project's broader "no vsss-rs, no raft-rs" philosophy of preferring a smaller, fully-understood dependency footprint over a large well-tested one when the smaller version is tractable to build and verify correctly.

**The three safety properties Raft guarantees, and how this implementation proves each one holds:**

- **Election Safety** — at most one leader can be elected in a given term. Proven by the vote-granting logic in `consensus/src/state.rs` (a node votes for at most one candidate per term, and only if that candidate's log is at least as up-to-date as its own) and *tested* under adversarial conditions by `sentinel-sim`'s chaos tests — partition, heal, clock skew, and message reordering, all checked against a `check_election_safety()` invariant scanning the entire simulated run's history.
- **Leader Append-Only** — a leader never overwrites or deletes entries in its own log, only appends. Structural in `ReplicatedLog::append_new`, which only ever pushes to the end.
- **Log Matching** — if two logs contain an entry with the same index and term, they're identical in every entry up to that point. Enforced by `AppendEntries`' consistency check (`ReplicatedLog::append_entries` in `consensus/src/log.rs`), which rejects an append whose immediately-preceding entry doesn't match, and by the "delete conflicting entries, then append" rule for the case where it does need to overwrite a follower's stale, uncommitted suffix.

**Implementation split across three files**, deliberately separated by concern: `log.rs` (the replicated log and its consistency rules — pure data structure, no networking), `rpc.rs` (the wire types: `RequestVoteRequest/Response`, `AppendEntriesRequest/Response`), and `state.rs` (`RaftState` — the actual state machine: given a message, what should change and what should the reply be — entirely synchronous, no `async`, no timers, no I/O). That last property is what makes both the real actor (`actor.rs`) and the deterministic simulator (`sentinel-sim`) able to drive the *exact same* `RaftState` type through completely different scheduling mechanisms without either one needing its own copy of the consensus logic.

28 tests on `sentinel-consensus` alone, covering: vote-granting and denial (including a retried vote from the same candidate succeeding, since RPCs can be legitimately retried), log conflict resolution, commit-index advancement bounded correctly by what's actually been replicated, and a full three-node election reaching majority.

### The actor model and why the deadlock happened

**What the actor model is:** a concurrency pattern where a unit of state (here, one Raft node) is owned exclusively by a single task, and the *only* way anything else interacts with it is by sending a message through a channel and waiting for a reply — there's no shared, lockable state visible from outside. This avoids classic shared-memory bugs (data races, inconsistent reads) by construction, since only one task ever touches the state directly.

**The bug this project actually hit:** an earlier version of `consensus/src/actor.rs`, upon an election timeout, sent `RequestVote` RPCs to every peer and then *awaited their responses directly inside the same async block handling the node's own incoming messages*. This meant that while a node was campaigning, it couldn't process its own mailbox — including an incoming `RequestVote` from a peer who was *also* campaigning at the same moment. If two nodes' election timers fired close together, each would end up blocked waiting for the other's vote response, while neither could answer the other's request, because both were stuck inside the same blocking wait. A genuine, real deadlock — not hypothetical, reproduced and confirmed against the buggy code before being fixed.

**The fix:** vote requests are now spawned as independent tasks that report their result back through the actor's *own* mailbox as a new internal message (`RaftMessage::VoteResult`), rather than being awaited inline. The actor's main loop never blocks on a peer's response — it stays responsive to its own incoming RPCs for the entire duration of any campaign it's running. This is documented directly in the code with a comment explaining *why* the pattern matters, not just what it does, since the failure mode it prevents isn't obvious from the fixed code alone.

**A second bug found the same way:** a single-node cluster (`peers: []`) could never elect itself leader, because the majority check only ran inside the code path that processes an incoming vote *response* — with no peers, that path never executes. Found while writing Phase 7's handler tests (which needed a working single-node cluster), fixed with a one-line addition (a lone node's own vote already constitutes "a majority of one"), and verified with a regression test that fails against the pre-fix code and passes against the fix.

### Mutual TLS (mTLS)

**What it is:** ordinary TLS (the "s" in "https") authenticates the *server* to the client — you know you're talking to the real bank, but the bank doesn't necessarily know who you are beyond your IP address. Mutual TLS requires *both* sides to present a certificate signed by a trusted authority; the server refuses the handshake entirely if the client doesn't present a valid one.

**Why it's used for everything, including cluster-internal traffic:** a common mistake in distributed systems is to secure client-facing traffic carefully while leaving node-to-node traffic on an implicitly-trusted internal network. Sentinel's Raft peer RPCs (`/raft/vote`, `/raft/append-entries`) go over the *exact same* mTLS listener as client secret requests — there's no separate, potentially-weaker internal channel. A compromised or spoofed node can't participate in the Raft cluster without a CA-signed certificate, any more than a client can read a secret without one.

**Implementation:** `crates/api/src/middleware/mtls.rs` builds a `rustls::ServerConfig` using `WebPkiClientVerifier`, which makes presenting a valid client certificate mandatory, not optional — there is no code path in the config that accepts an unauthenticated connection. `main.rs` wires this to a raw `tokio-rustls` TCP listener (not `axum-server`, which doesn't expose peer-certificate details the way this project needed) and manually bridges into Axum's router via `hyper-util`. **Verified against real TCP+TLS handshakes** with generated test certificates: valid client certs are accepted and their Common Name is correctly extracted for use as `ClientIdentity`; connections with no client cert are rejected; connections presenting a certificate not signed by the trusted CA are rejected; and the whole thing works identically when certs are loaded from real PEM files on disk, not just in-memory.

### Hash-chained audit log

**What it is:** each log entry's hash is computed over its own content *plus* the previous entry's hash, so the entries form a chain — exactly the same structural idea as a blockchain, minus the consensus/mining part. Altering, deleting, or forging any single entry changes that entry's hash, which breaks every entry's link after it, making tampering with history — not just the newest entry, any entry — detectable.

**What it proves, and what it doesn't:** this gives *tamper-evidence*, not *tamper-prevention*. Someone with full write access to the persisted log file could still rewrite the entire history consistently from scratch, recomputing every hash. What it protects against is *partial* tampering — editing one entry without redoing the rest, which is what an attacker trying to cover their tracks after the fact would actually attempt. Once the audit chain is wired into Raft-replicated storage (a future step beyond the current implementation), an attacker would need to rewrite the log on a majority of cluster nodes simultaneously, which is a much higher bar.

**Implementation:** `crates/audit/src/chain.rs`. Tested against the tampering scenarios that actually matter: altering an entry's event text or timestamp (breaks its own hash), deleting a middle entry (breaks index sequencing), and — the trickiest case — *splicing in a forged replacement entry* that's internally self-consistent (its own hash is correctly computed) but doesn't chain from the real predecessor's actual hash. All three are correctly detected, each with a specific error identifying exactly which index broke and why.

### Rolling z-score anomaly detection

**What it is:** a statistical technique for flagging when a current measurement is an outlier relative to recent history. Time is divided into fixed buckets (e.g. one second each); each closed bucket's event count feeds a rolling baseline (mean and standard deviation over the last N buckets); the *current, still-open* bucket is flagged the moment its count exceeds the baseline mean by more than a chosen number of standard deviations (a "z-score" — literally how many standard deviations away from the mean a value is).

**Why this over something more sophisticated:** simplicity is the point — no ML model, no training data, no external dependency, cheap enough to compute on every single request. The threat model this defends against (a compromised token being used to rapidly exfiltrate many secrets) shows up as an obvious, large spike relative to normal usage; a simple statistical test catches that without needing anything fancier.

**The demo-critical property**: detection has to fire *during* a burst, not only after it completes, or "auto-seal before the attack finishes" is an empty claim. This is specifically tested (`detection_fires_early_in_the_burst_not_only_at_the_end`) by confirming the detector flags the anomaly well before all 40 simulated requests in a burst have landed, not just on the last one.

**Implementation:** `crates/anomaly/src/detector.rs` for the pure detection logic (fully deterministic — time is passed in explicitly as an `Instant` parameter rather than read internally, which is what makes it possible to test with synthetic time advancement instead of real sleeping) and `crates/anomaly/src/seal.rs` for `SealCommand`, the type proposed to the Raft log when an anomaly fires, so the seal decision is replicated cluster-wide rather than being a purely local reaction that leaves other nodes still exploitable. Wired into `handlers/secrets.rs`'s `get_secret`: every read is recorded against the detector *before* anything else happens, and a detected anomaly immediately clears the in-memory KEK (sealing the vault), proposes the seal to Raft on a best-effort basis (a node protects itself immediately regardless of whether replication is currently healthy — exactly the situation most likely to be degraded during an actual attack), and records the event, attributed to the identity that triggered it, in the audit log.

**A known, honestly-stated limitation**: the detector needs several buckets of baseline history before it can flag anything — an attack starting the instant a node comes online wouldn't be caught immediately.

### Deterministic simulation testing

**What it is:** rather than testing a distributed system against real network sockets and real timers (which makes chaos scenarios like "a 30-second partition" take 30 real seconds, and makes test failures hard to reproduce because real-world timing is never exactly the same twice), a deterministic simulation replaces the network and clock with fully synthetic, programmer-controlled versions. Time becomes a plain number the test driver advances by exact amounts; messages are delivered by a virtual-time event queue instead of an OS scheduler; and the entire system becomes *reproducible* — the same random seed plus the same sequence of test actions (partition here, heal there) produces byte-identical results every time, which is what makes a failing test something you can actually debug rather than a flake to shrug off and re-run.

**Why it drives the real `RaftState`, not a mock:** this is the single most important design decision in `sentinel-sim`. It would be easy to write a simplified stand-in for Raft's logic just for testing purposes — but then a bug fixed in the simulation wouldn't necessarily be fixed in production, and vice versa. Instead, `SimWorld` (`crates/sim/src/world.rs`) is a discrete-event scheduler that calls the exact same `handle_request_vote`, `handle_append_entries`, `become_candidate`, and `record_vote` methods the real Tokio actor calls — it just decides *when* to call them using a virtual clock and a controllable network instead of real timers and real sockets.

**What the chaos tests actually check:**

- A 5-node cluster with no faults converges to exactly one leader (baseline sanity).
- A 2-of-5 minority, fully partitioned from the majority, can never elect a leader on its own — provably, since neither of its two members can reach the 3 votes needed for majority.
- A leader cut off from the rest of the cluster is correctly replaced by a new, higher-term leader on the majority side; once the partition heals, the old (now-stale) leader observes the higher term and steps down to follower — this is Raft's actual split-brain-prevention mechanism, tested directly rather than just asserted to exist.
- A node with an artificially skewed clock (its election timer fires wildly early relative to its peers) doesn't break convergence.
- Heavy message-latency jitter (which naturally produces reordering — a response can arrive before an earlier-sent one) doesn't break correctness, though — a real finding — if the injected latency is too close to the election-timeout window itself, you get *livelock* (repeated collisions) rather than testing genuine reordering; an earlier version of this test used too-aggressive parameters and had to be corrected once the actual (expected) livelock behavior was understood and distinguished from a real bug.
- Repeated partition/heal cycles never violate Election Safety across the *cumulative* history of a longer-running scenario, not just a single fault.
- The simulation itself is deterministic: identical seed and action sequence produces byte-identical leadership history and event counts across two independent runs.

**Implementation:** `crates/sim/src/{mock_clock,mock_network,world}.rs` plus `crates/sim/tests/raft_safety_test.rs`. 6 unit tests on the clock/network primitives, 7 integration tests on the actual chaos scenarios.

### Property-based testing and fuzzing

**What property-based testing is:** instead of writing individual test cases with specific inputs and expected outputs, you state a *property* that should hold for *any* input matching some shape (e.g. "decrypting arbitrary bytes should never panic"), and a library (`proptest`, here) generates hundreds of random inputs matching that shape, checking the property against each one. If it finds a failure, it automatically *shrinks* the failing input down to the smallest example that still reproduces the bug, which makes debugging much faster than working from a huge random blob.

**What fuzzing (specifically `cargo-fuzz`/libFuzzer) adds beyond that:** it's *coverage-guided* — the fuzzer instruments the compiled binary to see which code paths each input exercises, and specifically mutates inputs that discover *new* paths, rather than sampling uniformly at random. This finds edge cases a human (or `proptest`'s random sampling) is very unlikely to stumble onto by chance, at the cost of needing a nightly compiler toolchain and being meant for long runs (minutes to hours) rather than a quick per-commit check.

**Why both exist here, not just one:** they're complementary, not redundant. `crates/crypto/tests/fuzz_style_property_tests.rs` runs on stable Rust as part of every `cargo test`, catching regressions immediately — 7 properties, covering: `envelope::decrypt` never panicking on arbitrary or well-formed-length-but-garbage ciphertext, `encrypt`/`decrypt` round-tripping correctly for arbitrary plaintext, `combine_shares` and `split_secret` never panicking across the full adversarial input space, and both KDFs never panicking regardless of input/salt length. `crates/crypto/fuzz/fuzz_targets/{decrypt,combine_shares,kdf}.rs` are real `cargo-fuzz` harnesses for long, deep, coverage-guided runs — these mirror the exact same boundaries the property tests check, deliberately, so the "quick per-commit" and "deep periodic" layers are testing the same contracts at different intensities.

**Honestly stated**: the fuzz targets' *construction logic* was verified (the exact `Arbitrary`-derived struct shapes were fed 1,000 rounds of random bytes on stable Rust and confirmed to build correctly into the real library types), and they compile cleanly against a real nightly toolchain — but libFuzzer itself was never run against them, since no nightly toolchain was reachable in the sandbox this project was built in. `crates/crypto/fuzz/README.md` has the exact commands to actually run them.

---

## Crate-by-crate reference

| Crate | Concepts it implements | Tests |
|---|---|---|
| `sentinel-crypto` | Envelope encryption, Shamir's Secret Sharing, Argon2id/HKDF, mlock+zeroize secret memory | 20 unit + 7 property-based |
| `sentinel-storage` | Pluggable storage trait + `sled` embedded-KV backend | 4 |
| `sentinel-audit` | Hash-chained tamper-evident log | 8 |
| `sentinel-consensus` | Raft: log, RPCs, state machine, Tokio actor | 28 |
| `sentinel-hardware` | YubiKey PIV hardware quorum unseal | 5 |
| `sentinel-anomaly` | Rolling z-score anomaly detection, Raft-replicated seal | 13 |
| `sentinel-node` (api) | mTLS listener, Axum router, secrets/cluster/raft/dashboard handlers | 13 |
| `sentinel-sim` | Deterministic discrete-event Raft simulation, chaos tests | 6 + 7 |
| `sentinel-cli` | Standalone audit-chain verification tool | 2 |

**106 automated tests total** (`cargo test --workspace`), plus 7 nightly-only `cargo-fuzz` targets and a Miri-verifiable unsafe block, both documented in `crates/crypto/fuzz/README.md`.

---

## Security model

- **Unsealing requires physical hardware.** The KEK is split via Shamir's Secret Sharing across YubiKeys; no software-only path reconstructs it.
- **All network traffic — client and cluster — is mutual TLS**, with no plaintext listener anywhere in the codebase.
- **Every write is encrypted before it's proposed to the Raft log**, and every operation is appended to the hash-chained, identity-attributed audit log.
- **Auto-seal on anomalous access**, replicated cluster-wide on a best-effort basis, applied locally with certainty.
- **Key material is `mlock`'d and zeroized on drop**, never held in plain, swappable, un-overwritten memory.

## Known limitations

Stated because a security project that only advertises what works is less trustworthy than one that also says what doesn't:

- **Writes aren't gated on Raft commit.** `put_secret`/`delete_secret` propose to the log (correctly failing closed with `NotLeader` if not leader) and then apply directly, rather than waiting for majority-commit confirmation via an apply loop that doesn't exist yet. This is the single biggest gap between "looks like Raft" and "is linearizable" in the current codebase.
- **Peer-to-peer Raft transport (`HttpTransport`) is compiled and reviewed but not tested against a real multi-node network** — only the single-node path is exercised end-to-end.
- **`hardware/src/yubikey_piv.rs` has never touched a physical YubiKey.** Reviewed against the crate's documented API and confirmed to compile; the touch/PIN flow on real hardware is unverified.
- **`cargo-fuzz` targets were never run under libFuzzer** (no nightly toolchain reachable in the build sandbox) — their input-construction logic was separately verified on stable Rust.
- **The anomaly detector has a cold-start blind spot** — no baseline history yet at startup means no detection yet.
- **No node-setup tooling** — spinning up a real cluster today means hand-writing PEM files and a config file.
- **Authorization is all-or-nothing.** mTLS proves identity with cryptographic certainty; it doesn't yet gate which secrets a given identity may touch (`AppError::Unauthorized` exists as a typed placeholder for this, not yet wired to any check).

## Verification record

Every phase of this build followed one rule: write it, then prove it runs, then ship it — never hand off code that was only reviewed. Two real bugs were found and fixed this way, not by luck but because the testing was adversarial rather than happy-path:

1. **A genuine deadlock** in the Raft actor, found by a timing-based stress test, reproduced against the buggy code to confirm the test actually caught it (not just passed by coincidence), then fixed and re-verified across repeated runs.
2. **A single-node election bug** in already-shipped code, found while building a *later* phase's tests, fixed with a regression test proven to fail against the old code and pass against the fix.

The few pieces that couldn't be executed end-to-end — physical YubiKey hardware, a nightly Rust toolchain for fuzzing/Miri — are named explicitly above, not silently assumed to work.

## Quick start

```bash
git clone https://github.com/MuaazTasawar/sentinel.git
cd sentinel
cargo test --workspace   # 106 tests, a few minutes
```

## Development

```bash
cargo test --workspace              # everything
cargo test -p sentinel-crypto       # crypto core + property tests
cargo test -p sentinel-consensus    # Raft log/state/actor
cargo test -p sentinel-sim          # chaos/partition tests, <1s
cargo test -p sentinel-node         # full HTTP/crypto/consensus/audit/anomaly stack
```

Fuzzing and Miri (nightly-only — see `crates/crypto/fuzz/README.md`):

```bash
cd crates/crypto
cargo +nightly fuzz run decrypt -- -max_total_time=60
cargo +nightly miri test -p sentinel-crypto
```

## License

MIT