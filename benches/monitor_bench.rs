use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

/// Benchmark the inode cache building performance.
/// This is the main bottleneck in monitoring at high process counts.
fn bench_inode_cache(c: &mut Criterion) {
    let mut group = c.benchmark_group("inode_cache");

    // Sample at different process counts
    for size in [100, 500, 1000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &_size| {
            b.iter(|| {
                // Simulate building inode cache
                // In real benchmark, this would call build_inode_cache()
                black_box(simulate_inode_scan());
            });
        });
    }

    group.finish();
}

/// Simulate inode scanning (placeholder for real implementation)
fn simulate_inode_scan() -> Vec<(u64, u32, String)> {
    // This would actually scan /proc/*/fd/
    Vec::new()
}

/// Benchmark bandwidth rate parsing.
fn bench_rate_parse(c: &mut Criterion) {
    let inputs = ["100kb", "5mb", "1.5gb", "100kbit", "10mbit"];

    c.bench_function("rate_parse", |b| {
        b.iter(|| {
            for input in &inputs {
                black_box(parse_rate(input));
            }
        });
    });
}

/// Placeholder rate parser
fn parse_rate(s: &str) -> u64 {
    // Simplified parsing for benchmark
    let num: u64 = s
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0);

    if s.contains("gb") {
        num * 1_000_000_000
    } else if s.contains("mb") {
        num * 1_000_000
    } else if s.contains("kb") {
        num * 1_000
    } else {
        num
    }
}

/// Benchmark socket parsing from /proc/net/tcp
fn bench_socket_parse(c: &mut Criterion) {
    let sample_line = "  0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0";

    c.bench_function("socket_parse", |b| {
        b.iter(|| {
            black_box(parse_socket_line(black_box(sample_line)));
        });
    });
}

/// Placeholder socket parser
fn parse_socket_line(line: &str) -> Option<(u64, u64, u64)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 10 {
        Some((0, 0, 0)) // Simplified
    } else {
        None
    }
}

/// Benchmark full monitoring cycle
fn bench_monitor_cycle(c: &mut Criterion) {
    c.bench_function("monitor_cycle", |b| {
        b.iter(|| {
            // Simulate full monitoring cycle
            black_box(collect_bandwidth_stats());
        });
    });
}

/// Placeholder stats collection
fn collect_bandwidth_stats() -> Vec<u8> {
    Vec::with_capacity(1024)
}

criterion_group!(
    benches,
    bench_inode_cache,
    bench_rate_parse,
    bench_socket_parse,
    bench_monitor_cycle
);
criterion_main!(benches);
