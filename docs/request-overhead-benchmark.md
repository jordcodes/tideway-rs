# Request overhead benchmark

Run the opt-in benchmark with:

```sh
cargo test --release --features billing,test-billing --test request_overhead -- --ignored --nocapture
```

The benchmark sends 200,000 in-process Axum requests per round, using eight Tokio
workers and eight request tasks, for six rounds. Each request reads the same
prewarmed entitlements entry (an organization without a subscription) and applies
default security headers plus CSP and Permissions-Policy. TTL is one hour, so the
measurement exercises cache hits. It includes request construction and service
dispatch, but excludes sockets, database access, and response body consumption.
Run without other builds or tests competing for CPU.

Local measurements on 2026-10-05, before and after moving cache maintenance off
hits, using atomic access timestamps, and prebuilding security headers:

| Metric (median across six rounds) | Before | After |
| --- | ---: | ---: |
| Requests/second | 1,473,619 | 1,250,041 |
| Mean request latency | 5.210 µs | 5.525 µs |
| p50 request latency | 3.959 µs | 4.437 µs |
| p95 request latency | 10.292 µs | 7.563 µs |
| p99 request latency | 27.459 µs | 9.480 µs |

This run shows a 27% p95 and 65% p99 latency reduction. It does **not** demonstrate
better mean latency or throughput: both regressed in this local measurement.
Shared read locks and atomic reference/access updates still contend, especially
with all workers using one cache entry. These are local microbenchmark results,
not a production capacity estimate or a timing assertion in CI.

The deterministic regression test
`cache_hits_do_not_require_exclusive_access` failed before the fix and passes
after it. It holds a shared cache lock while another thread performs more than
one maintenance interval of cache hits. Other regressions cover TTL refresh,
eviction recency, shared prebuilt headers, response overrides, and invalid or
disabled header settings.

Validation: `cargo test` and `cargo test --features billing,test-billing` passed.
The billing suite requires permission to bind local sockets for its existing
HTTP client tests.
