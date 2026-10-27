//! Command-line surface: the output format is a subcommand.

use std::process::Command;

const IF_FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/module.if");

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sepol2nix"))
        .args(args)
        .output()
        .expect("runs sepol2nix")
}

#[test]
fn nix_command_prints_an_expression() {
    let output = run(&["nix", IF_FIXTURE]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("{\n  summary = \"Fixture module"),
        "{stdout}"
    );
}

#[test]
fn summary_command_prints_a_count() {
    let output = run(&["summary", IF_FIXTURE]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("2 macros"));
}

#[test]
fn tree_command_prints_the_ast() {
    let output = run(&["tree", IF_FIXTURE]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("InterfaceFile"));
}

#[test]
fn dialect_override_is_global() {
    let output = run(&["--dialect", "if", "summary", IF_FIXTURE]);
    assert!(output.status.success());
}

#[test]
fn unknown_command_fails() {
    let output = run(&["expand", IF_FIXTURE]);
    assert!(!output.status.success());
}

#[test]
fn parse_failure_exits_nonzero() {
    let path = std::env::temp_dir().join("sepol2nix-broken.te");
    std::fs::write(&path, "allow a b:file read\n").expect("writes");
    let output = run(&["summary", &path.to_string_lossy()]);
    assert!(!output.status.success());
    assert_ne!(output.stderr.len(), 0);
}

#[test]
fn substitute_usr_is_repeatable_on_nix() {
    let fc = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/module.fc");
    let output = run(&[
        "nix",
        fc,
        "--substitute-usr",
        "nix-store",
        "--substitute-usr",
        "system-path",
    ]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let commented = stdout.find("# \"/usr/bin/fixture\"").expect("commented");
    let store = stdout
        .find("\"/nix/store/[^/]+/bin/fixture\"")
        .expect("store");
    let system = stdout
        .find("\"@systemPath@/bin/fixture\"")
        .expect("system path");
    assert!(commented < store && store < system);
}

#[test]
fn substitute_usr_rejects_unknown_values() {
    let fc = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/module.fc");
    assert!(
        !run(&["nix", fc, "--substitute-usr", "fhs"])
            .status
            .success()
    );
    // The option belongs to the `nix` command only.
    assert!(
        !run(&["summary", fc, "--substitute-usr", "nix-store"])
            .status
            .success()
    );
}
