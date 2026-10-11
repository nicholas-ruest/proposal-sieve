# proposal-sieve

`proposal-sieve` is a fail-closed Rust CLI for auditing the complete network
surface of an agent, sandbox, or automation proposal before execution. It
checks every declared endpoint and redirect hop against a small TOML policy and
returns a CI-friendly `ALLOW` or `BLOCK` verdict.

It catches common whole-proposal bypasses that a single-URL allowlist misses:

- uninspected, duplicate, malformed, or empty endpoint declarations;
- disallowed scheme, host, port, path, method, or request-body size;
- embedded URL credentials, fragments, IP literals, and non-public addresses;
- redirect overflow, cross-origin redirects, and HTTPS-to-HTTP downgrades;
- undeclared policy fields, duplicate rule IDs, and unsupported policy versions.

The report includes deterministic finding codes, normalized URLs, matched rule
IDs, audited-target coverage, and a stable SHA-256 digest of the proposal.

## Install

Stable Rust is supported.

```console
cargo install --git https://github.com/nicholas-ruest/proposal-sieve
```

Or build from a clone:

```console
cargo build --release
```

## Use

Audit the included safe proposal:

```console
cargo run -- \
  --proposal examples/allowed.json \
  --policy examples/policy.toml
```

```text
proposal: inventory-check-42
digest: sha256:...
verdict: ALLOW
coverage: 2 endpoints / 2 targets audited
```

Machine-readable output is available with `--format json`:

```console
cargo run -- \
  --proposal examples/blocked.json \
  --policy examples/policy.toml \
  --format json
```

Exit codes are `0` for `ALLOW`, `2` for a policy `BLOCK`, and `1` for invalid
input, policy, or file access.

## Input model

Each proposal is a closed-world declaration. Every network target the caller
may reach, including expected redirect hops, must be present before audit.
`inspected = true` is an assertion from the integrating gateway that the target
was included in its inspection pass; the CLI verifies that the assertion is
present, but cannot observe runtime traffic.

Host rules are exact unless they start with `*.`. A wildcard such as
`*.example.com` matches `api.example.com`, but deliberately does not match the
apex `example.com`. Empty rule fields mean unconstrained for ports, paths, and
methods; schemes default to HTTPS. Security-sensitive defaults reject IP
literals, non-public IPs, cross-origin redirects, and more than three redirects.

## Verification

```console
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## Limitations

`proposal-sieve` is an offline structural gate. It does not resolve DNS, pin
addresses, intercept traffic, discover undeclared endpoints, validate TLS,
authenticate workloads, execute requests, or prove that runtime behavior
matches the proposal. Put it before a network-enforcing sandbox or proxy, and
bind the resulting proposal digest to that runtime's policy and audit receipt.

## License

MIT
