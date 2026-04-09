use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};

#[test]
fn test_rtl_unicode() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(0xD8, 1)])
        .unwrap()
        .with_window_size(10)
        .unwrap();
    let data = "שלום".as_bytes();
    let matches = filter.matching_windows(data);
    assert!(!matches.is_empty(), "Should handle RTL unicode bytes");
}

#[test]
fn test_combining_chars() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(0xCC, 1)])
        .unwrap()
        .with_window_size(10)
        .unwrap();
    let data = "é".as_bytes();
    let matches = filter.matching_windows(data);
    assert!(!matches.is_empty(), "Should handle combining characters");
}

#[test]
fn test_zero_width() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(0xE2, 1)])
        .unwrap()
        .with_window_size(10)
        .unwrap();
    let data = "\u{200B}".as_bytes();
    let matches = filter.matching_windows(data);
    assert!(!matches.is_empty(), "Should handle zero width characters");
}

#[test]
fn test_emojis() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(0xF0, 1)])
        .unwrap()
        .with_window_size(10)
        .unwrap();
    let data = "🚀".as_bytes();
    let matches = filter.matching_windows(data);
    assert!(!matches.is_empty(), "Should handle emoji characters");
}

#[test]
fn test_invalid_utf8() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(0xFF, 1)])
        .unwrap()
        .with_window_size(10)
        .unwrap();
    let data = vec![0xFF, 0xFF, 0xFF];
    let matches = filter.matching_windows(&data);
    assert!(!matches.is_empty(), "Should handle invalid UTF-8 bytes");
}

#[test]
fn test_extremely_large_window_with_small_threshold() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 1)])
        .unwrap()
        .with_window_size(usize::MAX)
        .unwrap();

    let mut data = vec![b'a'; 10_000];
    data[5000] = b'x';

    let matches = filter.matching_windows(&data);
    assert!(
        !matches.is_empty(),
        "Should handle usize::MAX window with matching data correctly"
    );
}

#[test]
fn test_duplicate_thresholds_for_same_byte() {
    let filter = ByteFrequencyFilter::new([
        ByteThreshold::new(b'x', 2),
        ByteThreshold::new(b'x', 5),
        ByteThreshold::new(b'x', 1),
    ])
    .unwrap()
    .with_window_size(10)
    .unwrap();

    let data = vec![b'x'; 4];
    let matches_fail = filter.matching_windows(&data);
    assert!(
        matches_fail.is_empty(),
        "Should use the highest requirement, so 4 is not enough for 5"
    );

    let data_success = vec![b'x'; 5];
    let matches_success = filter.matching_windows(&data_success);
    assert!(!matches_success.is_empty(), "5 should be enough");
}

#[test]
fn test_mixed_null_bytes_and_newlines() {
    let filter =
        ByteFrequencyFilter::new([ByteThreshold::new(0x00, 3), ByteThreshold::new(b'\n', 2)])
            .unwrap()
            .with_window_size(10)
            .unwrap();

    let data = b"abc\n\0\0def\0\nghi";
    let matches = filter.matching_windows(data);
    assert!(
        !matches.is_empty(),
        "Should match binary data mixed with newlines"
    );
}
