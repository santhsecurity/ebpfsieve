use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};

#[test]
fn test_all_bytes_same_as_threshold() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 5)])
        .unwrap()
        .with_window_size(5)
        .unwrap();
    let data = vec![b'x'; 1000];
    let matches = filter.matching_windows(&data);
    assert_eq!(
        matches.len(),
        1000 - 5 + 1,
        "Should find match at every single valid offset"
    );
}

#[test]
fn test_threshold_larger_than_window() {
    let result = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 10)])
        .unwrap()
        .with_window_size(5);

    if let Ok(filter) = result {
        let data = vec![b'x'; 100];
        let matches = filter.matching_windows(&data);
        assert!(
            matches.is_empty(),
            "Impossible configuration should yield 0 matches"
        );
    }
}

#[test]
fn test_threshold_larger_than_data() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 10)])
        .unwrap()
        .with_window_size(100)
        .unwrap();

    let data = b"xxxxx";
    let matches = filter.matching_windows(data);

    assert!(
        matches.is_empty(),
        "Threshold larger than data should never match"
    );
}

#[test]
fn test_window_larger_than_data_with_match() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 2)])
        .unwrap()
        .with_window_size(100)
        .unwrap();

    let data = b"xx";
    let matches = filter.matching_windows(data);

    assert_eq!(
        matches.len(),
        1,
        "Should match when data is smaller than window but meets threshold"
    );
    assert_eq!(
        matches[0].length, 2,
        "Reported window length should be capped at data length"
    );
}
