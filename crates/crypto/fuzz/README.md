# Fuzzing & Miri — `sentinel-crypto`

This crate has two layers of adversarial-input testing, and they're
complementary rather than redundant:

- **`tests/fuzz_style_property_tests.rs`** — property-based tests using
  `proptest`, run on stable Rust as part of the normal `cargo test`.
  These run on every commit and catch regressions immediately, but
  `proptest` only generates a few hundred inputs per property before
  stopping.
- **`fuzz/fuzz_targets/*.rs`** — real `cargo-fuzz` (libFuzzer) targets.
  These are coverage-guided: the fuzzer instruments the binary and keeps
  mutating inputs that discover new code paths, which finds edge cases a
  human (or `proptest`'s random sampling) is unlikely to hit by chance.
  They need a nightly toolchain and are meant for long runs (minutes to
  hours), not a quick CI check — that's what the property tests are for.

## Running the fuzz targets

Requires `cargo-fuzz` and a nightly toolchain (this is the one part of
this project's test suite I could not run myself — my sandbox has no
network access to `rust-lang.org`'s toolchain distribution, so I could
not install nightly to execute this. The targets are reviewed against
`libfuzzer-sys`/`arbitrary`'s documented API and the exact struct shapes
were verified separately by feeding them 1,000 rounds of arbitrary bytes
on stable Rust, but I have not personally watched libFuzzer run against
them).

```bash
cargo install cargo-fuzz
rustup toolchain install nightly

# From crates/crypto/:
cargo +nightly fuzz run decrypt
cargo +nightly fuzz run combine_shares
cargo +nightly fuzz run kdf
```

Each runs indefinitely until stopped (Ctrl+C) or until it finds a
crash. For a bounded CI-friendly run:

```bash
cargo +nightly fuzz run decrypt -- -max_total_time=60
```

A crash produces a minimized reproduction file under
`fuzz/artifacts/<target>/`; replay it with:

```bash
cargo +nightly fuzz run decrypt fuzz/artifacts/decrypt/<crash-file>
```

## Running Miri

Miri catches undefined behavior that fuzzing's black-box "did it crash"
check can't — specifically relevant here because `crypto/src/secret.rs`
contains this project's only hand-written `unsafe` code (the `mlock`/
`VirtualLock` calls backing `SecretBytes`). A fuzz crash would prove
something is *wrong*; Miri can prove the unsafe code has no UB even when
nothing crashes.

```bash
rustup toolchain install nightly --component miri
cargo +nightly miri test -p sentinel-crypto
```

**Known limitation, not a bug to chase**: Miri does not model `libc::mlock`
or Windows' `VirtualLock` — both are raw OS syscalls with no portable
semantics Miri's interpreter can execute. Expect Miri to either skip
these calls with a warning or reject them outright depending on your
Miri version. If it hard-fails specifically on the `mlock`/`VirtualLock`
call sites and nowhere else, that's an environment limitation of Miri
testing raw syscalls, not a memory-safety finding — the rest of
`secret.rs` (the `Vec` handling, the `zeroize` call, the `Drop` impl)
still gets Miri's full UB checking. If you want to isolate this, a
`#[cfg(miri)]` no-op stand-in for `lock`/`unlock` is a reasonable way to
let Miri check everything else in the file without tripping on the
syscall boundary — I have left that as a deliberate choice for whoever
runs this rather than silently disabling the real lock under Miri
without saying so.

I could not run this myself for the same reason as the fuzz targets —
no nightly toolchain reachable in my sandbox. This is the one piece of
Phase 11 I am handing off entirely rather than verifying first, and I
want that stated plainly rather than implied.