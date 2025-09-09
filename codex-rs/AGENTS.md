# Repository Guidelines

This workspace implements the Rust version of Codex CLI. Use this guide to navigate the codebase, run builds/tests, and contribute changes consistently.

## Project Structure & Module Organization

- Workspace root with crates in subfolders; crate names are prefixed with `codex-`.
- Key crates: `core/` (logic, crate `codex-core`), `tui/` (Terminal UI, `codex-tui`), `cli/` (multitool entrypoints), `exec/` (headless), `common/`, `protocol/`, `mcp-*`.
- Tests live alongside code (e.g., `tui/tests`, `core/src/...`), with snapshot tests in `tui`.

## Build, Test, and Development Commands

- Build: `cargo build` (workspace) or `cargo build -p codex-tui` (single crate).
- Run CLI: `just codex -- --help`, `just tui`, `just exec -- <args>`.
- Format: `just fmt` (required before commit).
- Lint/fix: `just fix -p <crate>` (scoped clippy fix; prefer `-p`).
- Tests (crate): `cargo test -p codex-tui`.
- Full tests (shared crates changed like `common/`, `core/`, `protocol/`): `cargo test --all-features`.
- Snapshots (tui): `cargo insta pending-snapshots -p codex-tui`, then `cargo insta accept -p codex-tui` if correct.

## Coding Style & Naming Conventions

- Rust 2024 edition; follow `rustfmt` and `clippy` settings in repo.
- Crate/package naming: prefix with `codex-` (e.g., folder `core` → crate `codex-core`).
- Prefer `format!("…{var}…")` with inline placeholders.
- TUI (ratatui) style: use `Stylize` helpers (`"text".dim().bold().cyan()`), avoid hardcoded white/black; see `tui/styles.md`.

## Testing Guidelines

- Use `insta` for snapshot tests in `tui`; review `.snap.new` before accept.
- Prefer `pretty_assertions::assert_eq!` in tests for readable diffs.
- Name tests clearly by behavior and module (e.g., `render_header_wraps` in `tui/tests/...`).

## Commit & Pull Request Guidelines

- Commit messages: imperative mood, concise scope prefix when useful (e.g., `tui: wrap long headers`).
- PRs: include summary, rationale, linked issues, and screenshots/recordings for TUI changes.
- Ensure `just fmt` passes; run `just fix -p <crate>` for lint fixes and targeted `cargo test -p <crate>` before requesting review.

## Security & Configuration Tips

- Sandboxing: CLI supports `--sandbox` (`read-only`, `workspace-write`, `danger-full-access`). Tests may respect `CODEX_SANDBOX*` envs to early-exit; do not remove these checks.
- Avoid adding network or filesystem side effects in tests unless guarded behind existing env checks.

