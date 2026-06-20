use std::env;
use std::process::Command;

/// Embeds a version string in the binary at compile time.
///
/// Prefers `git describe --tags --always --dirty` (e.g. `v2.1.0`, or
/// `v2.1.0-12-g345ff7b-dirty` between tags) so the reported version tracks the git
/// tag. Falls back to the `Cargo.toml` version when git is unavailable, such as when
/// building from a source tarball outside a repository.
fn main() {
    let version = git_describe().unwrap_or_else(|| {
        format!("v{}", env::var("CARGO_PKG_VERSION").unwrap())
    });
    println!("cargo:rustc-env=GIT_VERSION={version}");

    // Re-run this script (and thus refresh the embedded version) when the commit,
    // branch, or tags change.
    if let Some(git_dir) = run_git(&["rev-parse", "--git-dir"]) {
        for f in ["HEAD", "logs/HEAD", "refs/tags", "packed-refs"] {
            println!("cargo:rerun-if-changed={git_dir}/{f}");
        }
    }
}

fn git_describe() -> Option<String> {
    run_git(&["describe", "--tags", "--always", "--dirty"])
}

/// Runs `git` with the given args and returns trimmed stdout on success.
fn run_git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}
