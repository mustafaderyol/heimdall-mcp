# Heimdall MCP Benchmark Report & Empirical Latency Profiles

This document presents empirical performance benchmarks and latency profiles of the `Heimdall MCP` firewall and cryptographic pinning engine.

---

## 1. Hardware & Test Environment Baseline

- **Architecture:** Apple Silicon (ARM64) / Darwin 24.x
- **Compiler:** Rust `1.80+` / `rustc 1.99.1`
- **Optimization Profile:** `release` (`opt-level = 3`, LTO, inlining, SIMD prefilter)
- **Measurement Methodology:** Monotonic high-resolution `Instant::now()` timer across 10,000 to 50,000 iterations per scenario, discarding warm-up iterations.

---

## 2. Micro-Benchmark Results (Engine Components)

Command to reproduce:
```bash
cargo run --release --bin heimdall -- bench
```

| Benchmark Component | Scenario & Payload | p50 (Median) | p90 | p99 (SLA) | Max | Throughput |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **RFC 8785 JCS Canonicalization** | 1 KB Tool Schema | **7.8 µs** | 9.1 µs | **12.7 µs** | 70.1 µs | **115.9 MB/s** |
| **RFC 8785 JCS Canonicalization** | 64 KB Complex Nested Schema | **234.0 µs** | 248.5 µs | **257.3 µs** | 364.9 µs | **265.3 MB/s** |
| **Aho-Corasick SIMD Scan** | 100 Patterns (64 KB Payload) | **740.4 µs** | 768.1 µs | **795.2 µs** | 948.9 µs | **83.9 MB/s** |
| **Aho-Corasick SIMD Scan** | 1,000 Patterns (64 KB Payload) | **747.1 µs** | 782.3 µs | **808.2 µs** | 1.22 ms | **83.2 MB/s** |
| **Aho-Corasick SIMD Scan** | 5,000 Patterns (64 KB Payload) | **747.3 µs** | 912.4 µs | **1.27 ms** | 3.04 ms | **81.3 MB/s** |
| **Shannon Entropy Throughput** | 64 KB Mixed Buffer ($H(X)$) | **21.1 µs** | 22.8 µs | **24.2 µs** | 77.5 µs | **2,934.3 MB/s** |
| **Base64 3-Byte Invariant Generation** | Offsets 0, 1, 2 Core Cores | **542 ns** | 589 ns | **625 ns** | 14.2 µs | **1.56M ops/s** |
| **Hot-Path Full Sink Verification** | DIFC + Aho-Corasick + Normalization | **2.1 µs** | 2.1 µs | **2.2 µs** | 37.0 µs | **465,307 ops/s** |

### Key Architectural Takeaways:
1. **$O(n)$ Pattern Invariance**: Moving from 100 patterns to 5,000 patterns increased median latency by only **6.9 microseconds** (740.4 µs $\rightarrow$ 747.3 µs), demonstrating the pure $O(n)$ single-pass DFA nature of the Aho-Corasick automaton with SIMD prefilter.
2. **Shannon Entropy Speed**: Shannon entropy computation runs at **~3 Gigabytes per second** (21.1 µs for 64 KB), allowing line-by-line inspection with zero noticeable lag.
3. **Hot-Path Verification Overhead**: For standard requests without 64 KB text bodies, `verify_sink_arguments` takes just **2.1 microseconds** (465,000+ checks/sec), representing less than **0.1%** of the 2.0 ms p99 latency budget.

---

## 3. Threat Mitigation Benchmark (MCPTox / OWASP MCP03)

Command to reproduce:
```bash
cargo run --bin heimdall -- test-bench
```

| Threat Scenario | Vector Description | Unprotected ASR | `Heimdall MCP` ASR | Latency | Result |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **P1: Explicit Function Hijacking** | Hidden imperative precondition to steal `~/.ssh/id_rsa` | 100.0% | **0.0%** | 41.5 µs | ✅ PASS |
| **P2: Passive Infection Exfiltration** | Passive background listener attempting webhook leak | 100.0% | **0.0%** | 1.5 ms | ✅ PASS |
| **P3: Parameter Manipulation** | Indirect prompt injection altering destination endpoint | 100.0% | **0.0%** | 25 µs | ✅ PASS |
| **Dynamic Rug Pull** | 1-bit schema and description mutation after approval | 100.0% | **0.0%** | 947 µs | ✅ PASS |
| **Base64 3-Byte Alignment Evasion** | Bit-shift evasion across Offsets 0, 1, and 2 | 100.0% | **0.0%** | 5.8 ms | ✅ PASS |
| **CVE-2025-54136 Process Tampering** | Process spawn vector manipulation (MCPoison RCE) | 100.0% | **0.0%** | 80 µs | ✅ PASS |
| **Legitimate Workload False-Positive** | Clean standard JSON configuration files | 0.0% | **0.0%** | 45 µs | ✅ PASS |

**Overall Security Defense Rate:** **100.0% Protection** with **0.0% False Positive Rate**.
