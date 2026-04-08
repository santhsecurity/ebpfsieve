use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};

#[test]
fn test_sliding_window_updates() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 2)])
        .unwrap()
        .with_window_size(3)
        .unwrap();
    let data = b"axxa";
    let matches = filter.matching_windows(data);
    assert_eq!(matches.len(), 2, "Should correctly update counts when sliding");
}

#[test]
fn test_zero_count_threshold() {
    let result = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 0)]);
    assert!(result.is_err(), "Zero count threshold should be rejected");
    if let Err(e) = result {
        assert!(e.to_string().contains("greater than zero"), "Error message should be descriptive");
    }
}

#[test]
fn test_carry_over_bug_fix() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 2)])
        .unwrap()
        .with_window_size(4)
        .unwrap()
        .with_chunk_size(2)
        .unwrap();
        
    let data = b"axaxbxcx";
    let mut cursor = std::io::Cursor::new(data);
    let matches = filter.scan_file(&mut cursor, None).unwrap();
    
    assert_eq!(matches.len(), 5, "Should correctly handle carry over across small chunks");
}
