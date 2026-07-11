# Tideway Benchmarks

This directory contains repeatable performance benchmarks for Tideway's HTTP overhead and
security/concurrency-sensitive hot paths.

## Running Benchmarks

```bash
cargo bench

# Focused hot-path suite (enables its required optional modules)
cargo bench --bench hot_paths --features auth,jobs,websocket
```

## Benchmark Results

The benchmarks measure overhead introduced by Tideway's middleware and abstractions compared to raw Axum.

### Metrics

- **Hello World**: Simple text response comparison
- **JSON Response**: JSON serialization comparison
- **JWT verification**: HS256 access-token verification with issuer and audience checks
- **Rate limiting**: Per-IP middleware request cost
- **Request logging**: JSON body preview and sensitive-field redaction at 1 KiB and 16 KiB
- **Jobs**: In-memory enqueue/dequeue/complete cycle
- **WebSockets**: Broadcast fan-out to 10, 100, and 1,000 connected consumers

### Expected Results

Treat the first stable run on release hardware as the baseline. Compare changes on the same
machine and toolchain; shared CI runners are too noisy for strict absolute latency gates.

## Interpreting Results

Results are displayed as:
- Mean time per request
- Throughput (requests/second)
- Comparison percentage

Lower is better for time, higher is better for throughput.

Criterion stores baselines under `target/criterion`. To compare a change locally:

```bash
cargo bench --bench hot_paths --features auth,jobs,websocket -- --save-baseline main
# apply the change
cargo bench --bench hot_paths --features auth,jobs,websocket -- --baseline main
```

Investigate regressions above 15% on a stable runner. Confirm them with repeated runs before
treating them as release blockers.
