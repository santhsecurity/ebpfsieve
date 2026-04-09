use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};
use proptest::prelude::*;

#[test]
fn test_large_input_fuzzing() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 1)])
        .unwrap()
        .with_window_size(10)
        .unwrap();
    let data = vec![b'x'; 10_000];
    let matches = filter.matching_windows(&data);
    assert_eq!(
        matches.len(),
        10000 - 10 + 1,
        "Should find large matches safely"
    );
}

#[test]
fn test_extremely_large_max_matches() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 1)])
        .unwrap()
        .with_window_size(1)
        .unwrap()
        .with_max_matches(usize::MAX);

    let data = vec![b'x'; 10_000];
    let matches = filter.matching_windows(&data);
    assert_eq!(
        matches.len(),
        10_000,
        "Should handle usize::MAX max_matches safely"
    );
}

#[test]
fn test_all_thresholds_zero_except_one() {
    let mut thresholds = Vec::new();
    for i in 0..255 {
        if i == 42 {
            thresholds.push(ByteThreshold::new(i as u8, 1));
        } else {
            // Cannot use 0 directly as it is rejected
        }
    }

    let filter = ByteFrequencyFilter::new(thresholds)
        .unwrap()
        .with_window_size(10)
        .unwrap();
    let mut data = Vec::new();
    for i in 0..255 {
        data.push(i as u8);
    }

    let matches = filter.matching_windows(&data);
    assert_eq!(
        matches.len(),
        10,
        "Should find the exact windows containing byte 42"
    );
}

#[test]
fn test_alternating_bytes_dense() {
    let filter =
        ByteFrequencyFilter::new([ByteThreshold::new(b'0', 5), ByteThreshold::new(b'1', 5)])
            .unwrap()
            .with_window_size(10)
            .unwrap();

    let data = b"01010101010101010101"; // 20 bytes
    let matches = filter.matching_windows(data);
    assert_eq!(
        matches.len(),
        11,
        "Alternating bytes should produce 11 matches"
    );
}

#[test]
fn test_extremely_large_chunk_sizes() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 1)])
        .unwrap()
        .with_chunk_size(usize::MAX)
        .unwrap()
        .with_window_size(10)
        .unwrap();

    let data = b"xxxxxxxxxx".to_vec();
    let attachment = filter.attach(std::io::Cursor::new(data));
    assert_eq!(
        attachment.filter().chunk_size(),
        usize::MAX,
        "Filter created with extreme chunk size"
    );
}

#[test]
fn test_maximum_possible_threshold() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'y', u16::MAX)])
        .unwrap()
        .with_window_size(usize::MAX)
        .unwrap();

    let data = vec![b'y'; 100];
    let matches = filter.matching_windows(&data);
    assert!(
        matches.is_empty(),
        "Small data should safely fail large threshold"
    );
}

#[test]
fn test_all_possible_byte_thresholds() {
    let mut thresholds = Vec::new();
    for i in 0..=255 {
        thresholds.push(ByteThreshold::new(i as u8, 1));
    }

    let filter = ByteFrequencyFilter::new(thresholds)
        .unwrap()
        .with_window_size(256)
        .unwrap();

    let mut data = Vec::new();
    for i in 0..=255 {
        data.push(i as u8);
    }

    let matches = filter.matching_windows(&data);
    assert_eq!(
        matches.len(),
        1,
        "Exactly one window contains all bytes exactly once"
    );
}
