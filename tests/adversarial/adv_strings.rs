use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};

#[test]
fn test_adv_rtl_unicode() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(0xD8, 1)]).unwrap().with_window_size(10).unwrap();
    // Hebrew characters which are RTL
    let data = "שלום".as_bytes(); 
    let matches = filter.matching_windows(data);
    assert!(!matches.is_empty(), "Should handle RTL unicode bytes");
}

#[test]
fn test_adv_combining_chars() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(0xCC, 1)]).unwrap().with_window_size(10).unwrap();
    // 'e' with combining acute accent
    let data = "é".as_bytes();
    let matches = filter.matching_windows(data);
    assert!(!matches.is_empty(), "Should handle combining characters");
}

#[test]
fn test_adv_zero_width() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(0xE2, 1)]).unwrap().with_window_size(10).unwrap();
    // Zero width space
    let data = "\u{200B}".as_bytes();
    let matches = filter.matching_windows(data);
    assert!(!matches.is_empty(), "Should handle zero width characters");
}

#[test]
fn test_adv_emojis() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(0xF0, 1)]).unwrap().with_window_size(10).unwrap();
    // Emoji
    let data = "🚀".as_bytes();
    let matches = filter.matching_windows(data);
    assert!(!matches.is_empty(), "Should handle emoji characters");
}

#[test]
fn test_adv_invalid_utf8() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(0xFF, 1)]).unwrap().with_window_size(10).unwrap();
    // Invalid UTF-8 sequence
    let data = vec![0xFF, 0xFF, 0xFF];
    let matches = filter.matching_windows(&data);
    assert!(!matches.is_empty(), "Should handle invalid UTF-8 bytes");
}
