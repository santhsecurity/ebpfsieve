#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]
use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};
use std::sync::Arc;

#[cfg(all(target_os = "linux", feature = "socket-bpf"))]
use ebpfsieve::kernel::SocketFilterProgram;

#[test]
fn test_filter_with_zero_thresholds() {
    let result = ByteFrequencyFilter::new([]);
    assert!(result.is_err());
}

#[test]
fn test_filter_with_256_thresholds() {
    let thresholds: Vec<_> = (0..=255).map(|b| ByteThreshold::new(b, 1)).collect();
    let filter = ByteFrequencyFilter::new(thresholds)
        .unwrap()
        .with_window_size(256)
        .unwrap();
    let data: Vec<u8> = (0..=255).collect();
    let matches = filter.matching_windows(&data);
    assert_eq!(matches.len(), 1);
}

#[test]
fn test_window_size_larger_than_input() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_window_size(10)
        .unwrap();
    let matches = filter.matching_windows(b"a");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].length, 1);
}

#[test]
fn test_concurrent_matching_windows() {
    let filter = Arc::new(
        ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
            .unwrap()
            .with_window_size(1)
            .unwrap(),
    );
    let mut handles = vec![];
    for _ in 0..10 {
        let f = Arc::clone(&filter);
        handles.push(std::thread::spawn(move || {
            let matches = f.matching_windows(b"aaa");
            assert_eq!(matches.len(), 3);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn test_kernel_filter_prerequisites_non_linux() {
    use ebpfsieve::kernel::KernelFilter;
    let thresholds = vec![ByteThreshold::new(b'a', 1)];
    let result = KernelFilter::try_attach(&thresholds).unwrap();
    assert!(result.is_none());
}

#[cfg(all(target_os = "linux", feature = "socket-bpf"))]
#[test]
fn test_socket_filter_max_length_pattern() {
    let thresholds: Vec<_> = (0..=255).map(|b| ByteThreshold::new(b, 1)).collect();
    let filter = ByteFrequencyFilter::new(thresholds)
        .unwrap()
        .with_window_size(256)
        .unwrap();
    let result = SocketFilterProgram::try_load(&filter);

    match result {
        Ok(_) => {} // Load succeeds
        Err(e) => {
            // If it fails, it should be due to length limits or BPF issues
            assert!(
                e.to_string().contains("invalid filter configuration")
                    || e.to_string().contains("eBPF")
            );
        }
    }
}

#[test]
fn test_filter_with_max_matches_zero() {
    // max_matches=0 means it shouldn't return any matches
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_window_size(1)
        .unwrap()
        .with_max_matches(0);
    let matches = filter.matching_windows(b"a");
    assert_eq!(matches.len(), 0);
}

#[test]
fn test_max_window_size() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_window_size(usize::MAX)
        .unwrap();
    let matches = filter.matching_windows(b"a");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].length, 1);
}

#[test]
fn test_concurrent_matching_windows_large() {
    let filter = Arc::new(
        ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
            .unwrap()
            .with_window_size(1)
            .unwrap(),
    );
    let mut handles = vec![];
    for _ in 0..100 {
        let f = Arc::clone(&filter);
        handles.push(std::thread::spawn(move || {
            let data = vec![b'a'; 1000];
            let matches = f.matching_windows(&data);
            assert_eq!(matches.len(), 1000); // Because max_matches default is 1,000,000
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_256_thresholds_all_zero_count() {
    // 0 counts are rejected, so it should be Err
    let thresholds: Vec<_> = (0..=255).map(|b| ByteThreshold::new(b, 0)).collect();
    let result = ByteFrequencyFilter::new(thresholds);
    assert!(result.is_err());
}

#[test]
fn test_window_size_exactly_input_length() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 3)])
        .unwrap()
        .with_window_size(5)
        .unwrap();
    let matches = filter.matching_windows(b"xxaxx");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].length, 5);
}

#[test]
fn test_socket_filter_with_empty_filter() {
    // Should be caught at creation time, but let's test if we somehow bypass it
    // Wait, ByteFrequencyFilter cannot be created empty. We test the error format instead.
    let err = ByteFrequencyFilter::new([]).unwrap_err();
    assert!(err
        .to_string()
        .contains("at least one byte threshold is required"));
}
