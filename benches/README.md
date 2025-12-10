# Tideway Benchmarks

This directory contains performance benchmarks comparing Tideway to raw Axum.

## Running Benchmarks

```bash
cargo bench
```

## Benchmark Results

The benchmarks measure overhead introduced by Tideway's middleware and abstractions compared to raw Axum.

### Metrics

- **Hello World**: Simple text response comparison
- **JSON Response**: JSON serialization comparison
- **Rate Limiting**: Performance with rate limiting enabled
- **CORS**: Performance with CORS middleware
- **Full Stack**: All middleware enabled

### Expected Results

Tideway should have minimal overhead (<5%) compared to raw Axum, as it uses Axum's middleware stack efficiently.

## Interpreting Results

Results are displayed as:
- Mean time per request
- Throughput (requests/second)
- Comparison percentage

Lower is better for time, higher is better for throughput.

