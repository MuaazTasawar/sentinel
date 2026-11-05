//! Runs the real `sentinel-cli` binary with a stdout pipe that has no reader,
//! which is what `sentinel-cli ... | head` becomes once `head` has had enough.
//! Cargo builds the binary for integration tests, so this cannot run against
//! a stale one.
//!
//! The pipe is created here and its reader dropped *before* the child starts,
//! so the child's very first write is guaranteed to fail. (Closing the
//! child's pipe after spawning would race with the child's first print and
//! only sometimes reproduce the bug.)

use std::process::{Command, Output, Stdio};

fn run_with_closed_stdout(args: &[&str]) -> Output {
    let (reader, writer) = std::io::pipe().expect("create a pipe");
    drop(reader);
    Command::new(env!("CARGO_BIN_EXE_sentinel-cli"))
        .args(args)
        .stdout(writer)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sentinel-cli")
        .wait_with_output()
        .expect("wait for sentinel-cli")
}

#[test]
fn a_closed_stdout_pipe_neither_panics_nor_changes_the_exit_code() {
    let out = std::env::temp_dir().join(format!("sentinel-cli-pipe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    let out_arg = out.to_str().expect("utf-8 temp path");

    let output = run_with_closed_stdout(&[
        "init",
        "--holder",
        "a",
        "--holder",
        "b",
        "--threshold",
        "2",
        "--format",
        "plain",
        "--out",
        out_arg,
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !stderr.contains("panicked"),
        "must not panic on a closed pipe, stderr was:\n{stderr}"
    );
    assert!(
        output.status.success(),
        "init succeeded, so the exit status must too (got {:?}); stderr:\n{stderr}",
        output.status.code()
    );
    // ... and the work was really done, not abandoned halfway.
    assert!(
        out.join("canary.bin").exists(),
        "provisioning must still have completed"
    );

    let _ = std::fs::remove_dir_all(&out);
}

#[test]
fn a_real_failure_still_exits_non_zero_when_stdout_is_closed() {
    // `verify` on a file that does not exist must fail whether or not anyone
    // is reading its output.
    let output = run_with_closed_stdout(&["verify", "this-file-does-not-exist.jsonl"]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!stderr.contains("panicked"), "stderr was:\n{stderr}");
    assert!(
        !output.status.success(),
        "a failing verify must stay a failure"
    );
}
