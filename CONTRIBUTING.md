# Contributing to Heimdall MCP

We welcome community contributions, bug fixes, and security enhancements!

## Development Setup

1. **Prerequisites**:
   - Rust 1.80+ (`rustup default stable`)
   - Cargo

2. **Clone & Build**:
   ```bash
   git clone https://github.com/mustafaderyol/heimdall-mcp.git
   cd heimdall-mcp
   cargo build
   ```

3. **Run the Test Suite**:
   ```bash
   cargo test --all-targets
   ```

4. **Run the Threat Benchmark**:
   ```bash
   cargo run --bin heimdall -- test-bench
   ```

5. **Linting & Formatting**:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets -- -D warnings
   ```

## Pull Request Guidelines
- All PRs must pass CI (formatting, clippy, test suite, and benchmark).
- If adding new DIFC lattice rules or pattern matchers, please include corresponding unit tests in `tests/`.
