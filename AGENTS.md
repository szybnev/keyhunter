# Repository Guidelines

## Project Structure & Module Organization

KeyHunter is a Rust 2021 command-line application. Production code lives in
`src/`: `main.rs` defines the CLI and composes the application; `github.rs`
wraps GitHub API access; `scanner.rs` performs searches; `patterns.rs` defines
provider patterns and filtering; `verifier.rs` checks discovered credentials;
and `config.rs` parses configuration. Integration tests are in `tests/`, named
by feature (for example, `patterns_test.rs`). Keep example configuration in
`config.toml.example`; do not add real tokens. `assets/` contains README media.

## Build, Test, and Development Commands

- `cargo build` — compile a debug binary.
- `cargo build --release` — build the optimized `target/release/keyhunter`.
- `cargo test` — run the complete integration test suite.
- `cargo test --test patterns_test` — run one focused test target.
- `cargo fmt` — format Rust sources with rustfmt.
- `cargo clippy` — run Rust lints; address warnings before submitting.
- `cargo run -- scan -p openai` — run locally. Copy the example config first:
  `cp config.toml.example config.toml`, then supply a test GitHub token.

## Coding Style & Naming Conventions

Use rustfmt defaults (four-space indentation) and idiomatic Rust 2021. Name
modules, functions, fields, and test functions in `snake_case`; name types and
traits in `PascalCase`; name constants in `SCREAMING_SNAKE_CASE`. Prefer small,
focused functions and explicit `Result`-based error propagation with useful
context. Keep public structs and non-obvious behavior documented using `///`.
When adding a provider, update the pattern definition, scan/filter behavior,
configuration toggle, and relevant tests together.

## Testing Guidelines

Add or update a regression test for behavior changes. Place cross-module and
CLI-facing tests under `tests/`; use descriptive names such as
`test_openai_pattern_rejects_placeholder`. Tests must be deterministic: use
fixtures and sample values, never live API calls or real credentials. Run
`cargo fmt`, `cargo clippy`, and `cargo test` before review.

## Commit & Pull Request Guidelines

Recent history uses concise Conventional Commit-style subjects, e.g.
`feat: add provider pattern` or `fix: reject placeholder tokens`. Keep each
commit scoped to one meaningful change. Pull requests should explain the
behavioral change, list verification commands and results, link related issues
when applicable, and include CLI output or screenshots when user-visible
output changes. Never commit `config.toml`, scan results, or exposed secrets.

After every completed codebase update, run the relevant verification, then
create and push a scoped commit to the current upstream branch. Before staging,
inspect `git status` and include only files changed for that update; never
commit unrelated work, local configuration, results, or secrets. If pushing is
blocked by authentication, branch protection, conflicts, or an uncertain
target, stop and report the exact blocker instead of force-pushing.

## Security & Configuration

Use only authorized, public test targets when exercising scans or verification.
Treat findings as sensitive: redact values in logs, issues, fixtures, and PR
descriptions. Keep tokens in ignored local configuration or environment-managed
secrets, and rotate any credential accidentally exposed during development.
