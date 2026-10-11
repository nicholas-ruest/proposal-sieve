use clap::{Parser, ValueEnum};
use proposal_sieve::{Policy, Proposal, Report, audit};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// JSON document containing the complete proposed endpoint set.
    #[arg(long)]
    proposal: PathBuf,
    /// TOML policy used to audit every target and redirect hop.
    #[arg(long)]
    policy: PathBuf,
    /// Report encoding.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(report) => {
            match cli.format {
                OutputFormat::Text => print_text(&report),
                OutputFormat::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .expect("report serialization cannot fail")
                ),
            }
            if report.allowed {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Err(message) => {
            eprintln!("proposal-sieve: {message}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: &Cli) -> Result<Report, String> {
    let proposal_input = fs::read_to_string(&cli.proposal)
        .map_err(|error| format!("cannot read {}: {error}", cli.proposal.display()))?;
    let policy_input = fs::read_to_string(&cli.policy)
        .map_err(|error| format!("cannot read {}: {error}", cli.policy.display()))?;
    let proposal = Proposal::from_json(&proposal_input).map_err(|error| error.to_string())?;
    let policy = Policy::from_toml(&policy_input).map_err(|error| error.to_string())?;
    Ok(audit(&proposal, &policy))
}

fn print_text(report: &Report) {
    println!("proposal: {}", report.proposal_id);
    println!("digest: {}", report.proposal_digest);
    println!(
        "verdict: {}",
        if report.allowed { "ALLOW" } else { "BLOCK" }
    );
    println!(
        "coverage: {} endpoints / {} targets audited",
        report.endpoint_count, report.audited_target_count
    );
    for finding in &report.findings {
        println!(
            "- {} [{}] {}: {}",
            finding.code, finding.endpoint_id, finding.target, finding.message
        );
    }
}
