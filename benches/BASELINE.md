# Hot-path benchmark baseline

Indicative local baseline captured on 2026-07-11 using arm64 macOS 26.5 and
`rustc 1.94.1`. These values are orientation points, not cross-machine SLAs.

Command:

```bash
cargo bench --bench hot_paths --features auth,jobs,websocket -- \
  --warm-up-time 1 --measurement-time 2 --sample-size 20
```

| Workload | Median estimate |
| --- | ---: |
| HS256 access-token verification | 1.87 µs |
| Per-IP rate-limit middleware request | 1.05 µs |
| 1 KiB JSON request logging/redaction | 5.40 µs |
| 16 KiB JSON request logging/redaction | 22.17 µs |
| In-memory enqueue/dequeue/complete | 1.38 µs |
| WebSocket broadcast to 10 consumers | 2.18 µs |
| WebSocket broadcast to 100 consumers | 8.74 µs |
| WebSocket broadcast to 1,000 consumers | 73.75 µs |

Use Criterion baselines on the same machine for regression decisions. Investigate changes above
15%, then repeat the run to distinguish persistent regressions from system noise.
