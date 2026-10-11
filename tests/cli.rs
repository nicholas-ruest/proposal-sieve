use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

fn example(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join(name)
}

#[test]
fn allows_a_fully_audited_proposal() {
    Command::cargo_bin("proposal-sieve")
        .unwrap()
        .args([
            "--proposal",
            example("allowed.json").to_str().unwrap(),
            "--policy",
            example("policy.toml").to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("verdict: ALLOW"));
}

#[test]
fn blocks_a_proposal_with_an_unaudited_target() {
    Command::cargo_bin("proposal-sieve")
        .unwrap()
        .args([
            "--proposal",
            example("blocked.json").to_str().unwrap(),
            "--policy",
            example("policy.toml").to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("endpoint-uninspected"))
        .stdout(predicate::str::contains("redirect-cross-origin"));
}

#[test]
fn emits_machine_readable_json() {
    Command::cargo_bin("proposal-sieve")
        .unwrap()
        .args([
            "--proposal",
            example("allowed.json").to_str().unwrap(),
            "--policy",
            example("policy.toml").to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"allowed\": true"))
        .stdout(predicate::str::contains("\"proposal_digest\": \"sha256:"));
}
