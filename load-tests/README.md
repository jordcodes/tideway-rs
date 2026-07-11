# Tideway integration load tests

This opt-in harness measures end-to-end HTTP, authentication, PostgreSQL, and WebSocket behavior
using a small app that follows Tideway's generated route and database conventions.

Requirements:

- Docker with Compose
- `oha` (`cargo install oha --version 1.14.0 --locked`)
- Rust toolchain

Run:

```bash
./scripts/load-test.sh
```

Configuration:

```bash
DURATION=60s CONCURRENCY=100 WS_CLIENTS=1000 ./scripts/load-test.sh
```

JSON results are written to a timestamped directory under `load-tests/results/`. Compare runs on
the same machine and investigate persistent throughput or p95/p99 latency regressions above 15%.
Shared CI results are trend indicators, not hard release gates.

Workloads:

- Health endpoint baseline
- HS256 authenticated endpoint with issuer/audience validation
- Per-IP rate-limit middleware under sustained concurrency
- Paginated and filtered PostgreSQL resource endpoint over 10,000 seeded rows
- WebSocket connection setup and one-to-many broadcast delivery
