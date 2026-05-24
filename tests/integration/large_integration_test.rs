use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};

#[test]
fn e2e_scan_large_dataset() {
    let mut data = Vec::with_capacity(10 * 1024 * 1024);
    for i in 0..10 * 1024 * 1024 {
        data.push((i % 256) as u8);
    }

    // Pattern: 10 occurrences of 'A', 10 occurrences of 'B'
    let filter =
        ByteFrequencyFilter::new([ByteThreshold::new(b'A', 10), ByteThreshold::new(b'B', 10)])
            .unwrap()
            .with_window_size(1000)
            .unwrap();

    let matches = filter.matching_windows(&data);
    assert!(
        matches.len() > 0,
        "Should find matches in the cyclic buffer"
    );
}

#[test]
fn e2e_scan_sparse_dataset() {
    let mut data = vec![0u8; 10 * 1024 * 1024];
    data[1000000] = b'X';
    data[1000001] = b'X';
    data[1000002] = b'X';

    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'X', 3)])
        .unwrap()
        .with_window_size(10)
        .unwrap();

    let matches = filter.matching_windows(&data);
    assert_eq!(
        matches.len(),
        8,
        "Exact match count in sparse data should be predictable"
    );
}

#[test]
fn e2e_scan_dense_dataset() {
    let data = vec![b'Y'; 10 * 1024 * 1024];
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'Y', 100)])
        .unwrap()
        .with_window_size(100)
        .unwrap();

    let matches = filter.matching_windows(&data);
    // 1M limit
    assert_eq!(matches.len(), 1_000_000, "Should hit max_matches limit");
}
