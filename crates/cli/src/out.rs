//! Console output that survives a closed pipe.
//!
//! `println!` panics when stdout is a pipe whose reader has gone away, which
//! is exactly what `sentinel-cli ... | head` does: the CLI printed a panic
//! message and exited with status 101. Here a *broken pipe* means "nobody is
//! reading any more", which is not an error worth dying for, so that one
//! error kind is discarded.
//!
//! Two properties matter and are tested:
//!
//! * Only `BrokenPipe` is swallowed. Any other failure to write (a full
//!   disk behind a redirect, say) still stops the program with a message and
//!   a non-zero status, because silently losing output would be worse.
//! * The program carries on after a broken pipe instead of exiting early, so
//!   **exit codes are unchanged**: `verify` still fails with a non-zero
//!   status on a tampered log even when its report could not be printed.

use std::io::{self, Write};

/// Writes `args` (and a newline) to `w`.
pub(crate) fn write_line_to<W: Write>(w: &mut W, args: std::fmt::Arguments<'_>) -> io::Result<()> {
    w.write_fmt(args)?;
    w.write_all(b"\n")?;
    w.flush()
}

/// A closed pipe is not an error; everything else is.
pub(crate) fn ignore_broken_pipe(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}

/// Backs the [`outln!`] macro.
pub(crate) fn print_line(args: std::fmt::Arguments<'_>) {
    let result = ignore_broken_pipe(write_line_to(&mut io::stdout().lock(), args));
    if let Err(e) = result {
        eprintln!("error: cannot write to stdout: {e}");
        std::process::exit(1);
    }
}

/// Like `println!`, but a closed pipe does not panic.
macro_rules! outln {
    () => { $crate::out::print_line(format_args!("")) };
    ($($arg:tt)*) => { $crate::out::print_line(format_args!($($arg)*)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A writer that fails every call with the given error kind.
    struct Failing(io::ErrorKind);
    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(self.0))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(self.0))
        }
    }

    #[test]
    fn a_line_is_written_with_a_trailing_newline() {
        let mut buf = Vec::new();
        write_line_to(&mut buf, format_args!("sealed {}", 3)).unwrap();
        assert_eq!(buf, b"sealed 3\n");
    }

    #[test]
    fn a_closed_pipe_is_not_an_error() {
        let r = write_line_to(&mut Failing(io::ErrorKind::BrokenPipe), format_args!("x"));
        assert!(r.is_err(), "the underlying write does fail");
        assert!(
            ignore_broken_pipe(r).is_ok(),
            "but a broken pipe is discarded"
        );
    }

    #[test]
    fn every_other_write_failure_is_still_an_error() {
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::StorageFull,
            io::ErrorKind::WriteZero,
            io::ErrorKind::Other,
        ] {
            let r = write_line_to(&mut Failing(kind), format_args!("x"));
            let e = ignore_broken_pipe(r).expect_err("must not be swallowed");
            assert_eq!(e.kind(), kind);
        }
    }
}
