use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sharp_edr_checker::edr_data;

fn benchmark_signature_matching(c: &mut Criterion) {
    c.bench_function("find_matches_single_hit", |b| {
        b.iter(|| {
            edr_data::find_matches(black_box("CrowdStrike Falcon Sensor Service"))
        })
    });

    c.bench_function("find_matches_no_hit", |b| {
        b.iter(|| {
            edr_data::find_matches(black_box("Microsoft Windows Update Service"))
        })
    });

    c.bench_function("find_matches_multiple_hits", |b| {
        b.iter(|| {
            edr_data::find_matches(black_box(
                "Windows Defender Anti-Virus Malware Protection Service"
            ))
        })
    });

    c.bench_function("find_matches_long_text", |b| {
        let long_text = "This is a very long service description that contains \
                         information about CrowdStrike endpoint protection and \
                         various other security features including malware detection \
                         and anti-virus capabilities running on Windows Defender \
                         with additional components from Sophos and Symantec \
                         providing comprehensive endpoint security monitoring.";
        b.iter(|| edr_data::find_matches(black_box(long_text)))
    });
}

#[cfg(windows)]
fn benchmark_windows_api(c: &mut Criterion) {
    use sharp_edr_checker::{directory, privilege};

    c.bench_function("privilege_check", |b| {
        b.iter(|| privilege::check_is_admin())
    });

    c.bench_function("directory_check", |b| {
        b.iter(|| directory::check_directories())
    });
}

#[cfg(not(windows))]
fn benchmark_windows_api(_c: &mut Criterion) {
    // Windows-specific benchmarks skipped on non-Windows platforms
}

criterion_group!(
    benches,
    benchmark_signature_matching,
    benchmark_windows_api
);
criterion_main!(benches);
