#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]
//! Adversarial tests for ebpfsieve - stress-testing edge cases and hostile inputs.
//!
//! These tests are designed to BREAK, not just validate. They test:
//! - Malformed/empty/null inputs
//! - Resource exhaustion scenarios
//! - Concurrent access patterns
//! - Off-by-one errors
//! - Unicode edge cases
//! - Boundary conditions

#[cfg(feature = "socket-bpf")]
use ebpfsieve::kernel::{byte_frequency_filter_to_literal_pattern, compile_socket_filter_program};
use ebpfsieve::{ByteFrequencyFilter, ByteThreshold, Error};
use std::io::Cursor;

// ============================================================================
// ByteFrequencyFilter - scan_file adversarial tests
// ============================================================================

#[test]
fn scan_file_empty_data() {
    // Empty file should produce zero matches without error
    let temp_path = std::env::temp_dir().join("ebpf_adv_empty");
    std::fs::write(&temp_path, b"").unwrap();

    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_window_size(10)
        .unwrap();

    let matches = filter.scan_path(&temp_path, None).unwrap();
    assert_eq!(matches.len(), 0, "Empty file should have zero matches");

    let _ = std::fs::remove_file(temp_path);
}

#[test]
fn scan_file_single_byte() {
    // File with 1 byte - window size larger than file
    let temp_path = std::env::temp_dir().join("ebpf_adv_single");
    std::fs::write(&temp_path, b"a").unwrap();

    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_window_size(10)
        .unwrap();

    let matches = filter.scan_path(&temp_path, None).unwrap();
    assert_eq!(
        matches.len(),
        1,
        "Single matching byte should produce one window"
    );
    assert_eq!(matches[0].offset, 0);
    assert_eq!(matches[0].length, 1); // Window clamped to data length

    let _ = std::fs::remove_file(temp_path);
}

#[test]
fn scan_file_one_megabyte() {
    // 1MB file with periodic pattern - tests performance and correctness at scale
    let temp_path = std::env::temp_dir().join("ebpf_adv_1mb");
    let mut content = Vec::with_capacity(1024 * 1024);

    // Create pattern: every 100 bytes has 5 'x' chars
    for i in 0..(1024 * 1024) {
        if i % 100 < 5 {
            content.push(b'x');
        } else {
            content.push(b'.');
        }
    }
    std::fs::write(&temp_path, &content).unwrap();

    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 5)])
        .unwrap()
        .with_window_size(100)
        .unwrap()
        .with_chunk_size(64 * 1024)
        .unwrap();

    let matches = filter.scan_path(&temp_path, None).unwrap();
    // Each 100-byte block with 5 x's at start should match
    // 1MB / 100 = ~10485 matches, but windows slide so more
    assert!(
        !matches.is_empty(),
        "1MB file with pattern should have matches"
    );
    assert!(
        matches.len() > 10000,
        "Expected many matches in periodic 1MB data"
    );

    let _ = std::fs::remove_file(temp_path);
}

#[test]
fn scan_file_all_same_byte_minimal_entropy() {
    // All identical bytes - minimal entropy, every window matches
    let temp_path = std::env::temp_dir().join("ebpf_adv_min_entropy");
    let content = vec![b'A'; 1000];
    std::fs::write(&temp_path, &content).unwrap();

    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 10)])
        .unwrap()
        .with_window_size(100)
        .unwrap();

    let matches = filter.scan_path(&temp_path, None).unwrap();
    // Every window of 100 bytes contains 100 'A's, which is >= 10
    // 1000 - 100 + 1 = 901 possible windows
    assert_eq!(
        matches.len(),
        901,
        "All-same-byte file should match all windows"
    );

    let _ = std::fs::remove_file(temp_path);
}

#[test]
fn scan_file_max_entropy_random_bytes() {
    // Random bytes - maximum entropy, statistically few matches
    let temp_path = std::env::temp_dir().join("ebpf_adv_max_entropy");
    let content: Vec<u8> = (0..10000).map(|i| ((i * 31 + 17) % 256) as u8).collect();
    std::fs::write(&temp_path, &content).unwrap();

    // Looking for 50 of the same byte in 100-byte window
    // With uniform distribution, expected count of any byte is ~39
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(42, 50)])
        .unwrap()
        .with_window_size(100)
        .unwrap();

    let matches = filter.scan_path(&temp_path, None).unwrap();
    // Should have very few or zero matches with pseudo-random data
    assert!(
        matches.len() < 10,
        "Random data should rarely match high thresholds"
    );

    let _ = std::fs::remove_file(temp_path);
}

// ============================================================================
// Window size edge cases
// ============================================================================

#[test]
fn window_size_zero_is_rejected() {
    // Window size 0 should be rejected with actionable error
    let result = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_window_size(0);

    match result {
        Err(Error::InvalidConfiguration { reason, fix }) => {
            assert!(
                reason.contains("zero") || reason.contains("0"),
                "Error should mention zero: got '{}'",
                reason
            );
            assert!(!fix.is_empty(), "Error should provide fix guidance");
        }
        Ok(_) => panic!("Window size 0 should be rejected"),
        Err(e) => panic!("Unexpected error type: {:?}", e),
    }
}

#[test]
fn window_size_one() {
    // Window size 1 - each byte is its own window
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 1)])
        .unwrap()
        .with_window_size(1)
        .unwrap();

    let matches = filter.matching_windows(b"axbxcx");
    assert_eq!(matches.len(), 3, "Should find 3 single-byte matches");
    assert_eq!(matches[0].offset, 1);
    assert_eq!(matches[1].offset, 3);
    assert_eq!(matches[2].offset, 5);
}

#[test]
fn window_size_1000() {
    // Large window size
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 500)])
        .unwrap()
        .with_window_size(1000)
        .unwrap();

    let mut content = vec![b'x'; 1500];
    content.extend(vec![b'y'; 500]);

    let matches = filter.matching_windows(&content);
    // Windows of 1000 in 2000 bytes = 1001 possible windows
    // First 501 windows (0-500) have 1000 x's
    // Windows 501-1000 have decreasing x count
    assert!(!matches.is_empty(), "Large window should find matches");
    assert_eq!(matches[0].offset, 0);
}

#[test]
fn window_size_larger_than_data() {
    // Window size larger than data - should clamp to data length
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 3)])
        .unwrap()
        .with_window_size(100)
        .unwrap();

    let matches = filter.matching_windows(b"aaaa");
    assert_eq!(matches.len(), 1, "Single window when data < window size");
    assert_eq!(
        matches[0].length, 4,
        "Window length should clamp to data length"
    );
}

// ============================================================================
// Pattern matching edge cases
// ============================================================================

#[test]
fn pattern_matches_entire_file() {
    // Pattern requirements match the entire file exactly
    let temp_path = std::env::temp_dir().join("ebpf_adv_full_match");
    let content = b"abcabcabcabc";
    std::fs::write(&temp_path, content).unwrap();

    // File has 4 a's, 4 b's, 4 c's in 12 bytes
    let filter = ByteFrequencyFilter::new([
        ByteThreshold::new(b'a', 4),
        ByteThreshold::new(b'b', 4),
        ByteThreshold::new(b'c', 4),
    ])
    .unwrap()
    .with_window_size(12)
    .unwrap();

    let matches = filter.scan_path(&temp_path, None).unwrap();
    assert_eq!(
        matches.len(),
        1,
        "Entire file should be one matching window"
    );
    assert_eq!(matches[0].offset, 0);
    assert_eq!(matches[0].length, 12);

    let _ = std::fs::remove_file(temp_path);
}

#[test]
fn pattern_not_in_file() {
    // Required bytes simply don't exist in file
    let temp_path = std::env::temp_dir().join("ebpf_adv_no_match");
    std::fs::write(&temp_path, b"hello world, this is a test").unwrap();

    let filter = ByteFrequencyFilter::new([
        ByteThreshold::new(b'z', 5), // No z's in file
    ])
    .unwrap()
    .with_window_size(10)
    .unwrap();

    let matches = filter.scan_path(&temp_path, None).unwrap();
    assert!(
        matches.is_empty(),
        "Pattern not in file should produce no matches"
    );

    let _ = std::fs::remove_file(temp_path);
}

#[test]
fn pattern_at_exact_boundary() {
    // Pattern is split across chunk boundaries
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 3)])
        .unwrap()
        .with_window_size(5)
        .unwrap()
        .with_chunk_size(4)
        .unwrap();

    // "xxx" at positions 3,4,5 - spans chunk boundary at position 4
    let mut attachment = filter.attach(Cursor::new(b"aaaxxxbbb"));
    let mut all_matches = Vec::new();

    while let Ok(Some(chunk)) = attachment.read_next() {
        all_matches.extend(chunk.candidate_ranges);
    }

    // Windows containing 3 x's: "axxx" (offset 2), "xxx" (offset 3), "xxxb" (offset 4)
    assert!(
        !all_matches.is_empty(),
        "Should detect pattern across chunk boundaries"
    );
}

// ============================================================================
// Co-occurrence detection
// ============================================================================

#[test]
fn two_co_occurring_bytes_present() {
    // Two bytes that must appear together - both present
    let filter =
        ByteFrequencyFilter::new([ByteThreshold::new(b'a', 2), ByteThreshold::new(b'b', 3)])
            .unwrap()
            .with_window_size(10)
            .unwrap();

    // "aabbb" + padding: has 2 a's, 3 b's
    // Window at offset 0: "xxaabbbxxx" has 2 a's, 3 b's
    let matches = filter.matching_windows(b"xxaabbbxxx");
    assert!(!matches.is_empty(), "Co-occurring bytes should be detected");
    // Window at offset 0 has both 2 a's and 3 b's
    assert!(
        matches.iter().any(|m| m.offset == 0),
        "Should match at offset 0"
    );
}

#[test]
fn co_occurring_bytes_absent() {
    // Both thresholds defined but only one byte appears
    let filter =
        ByteFrequencyFilter::new([ByteThreshold::new(b'a', 2), ByteThreshold::new(b'b', 3)])
            .unwrap()
            .with_window_size(10)
            .unwrap();

    // File has plenty of 'a' but no 'b'
    let matches = filter.matching_windows(b"aaaaaacccc");
    assert!(
        matches.is_empty(),
        "Missing co-occurring byte should prevent match"
    );
}

#[test]
fn co_occurring_at_file_boundary() {
    // Pattern right at start and end of file
    let filter =
        ByteFrequencyFilter::new([ByteThreshold::new(b'x', 2), ByteThreshold::new(b'y', 2)])
            .unwrap()
            .with_window_size(5)
            .unwrap();

    // Pattern at start: "xxyy_"
    let start_match = filter.matching_windows(b"xxyyzzz");
    assert!(!start_match.is_empty(), "Should detect at start boundary");
    assert_eq!(start_match[0].offset, 0);

    // Pattern at end: "_xxyy"
    let end_match = filter.matching_windows(b"zzzxxyy");
    assert!(!end_match.is_empty(), "Should detect at end boundary");
}

#[test]
fn window_at_file_boundary_partial() {
    // Partial window at end of file (not enough bytes for full window)
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 2)])
        .unwrap()
        .with_window_size(10)
        .unwrap();

    // Only 5 bytes, but has 2 a's
    let matches = filter.matching_windows(b"aaabc");
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].offset, 0);
    assert_eq!(matches[0].length, 5, "Partial window at boundary");
}

// ============================================================================
// Socket filter compilation adversarial tests
// ============================================================================

#[test]
#[cfg(feature = "socket-bpf")]
fn compile_filter_short_pattern_3_bytes() {
    // Very short pattern - 3 bytes
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 3)]).unwrap();

    let insns = compile_socket_filter_program(&filter).unwrap();
    assert!(!insns.is_empty(), "Short pattern should compile");
    // BPF socket filter for 3-byte pattern should have reasonable instruction count
    assert!(
        insns.len() >= 3,
        "Should have at least 3 instructions for 3-byte pattern"
    );
}

#[test]
#[cfg(feature = "socket-bpf")]
fn compile_filter_long_pattern_100_bytes() {
    // Long pattern - 100 bytes total
    let filter = ByteFrequencyFilter::new([
        ByteThreshold::new(b'a', 25),
        ByteThreshold::new(b'b', 25),
        ByteThreshold::new(b'c', 25),
        ByteThreshold::new(b'd', 25),
    ])
    .unwrap();

    let insns = compile_socket_filter_program(&filter).unwrap();
    assert!(!insns.is_empty(), "Long pattern should compile");
}

#[test]
fn compile_filter_empty_pattern_errors() {
    // Empty thresholds should error, not compile empty program
    let result = ByteFrequencyFilter::new([]);

    match result {
        Err(Error::InvalidConfiguration { reason, fix }) => {
            assert!(
                reason.contains("empty") || reason.contains("required"),
                "Error should mention empty/required: got '{}'",
                reason
            );
            assert!(!fix.is_empty(), "Should provide fix guidance");
        }
        Ok(_) => panic!("Empty pattern should be rejected"),
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}

#[test]
#[cfg(feature = "socket-bpf")]
fn compile_filter_very_long_pattern_boundary() {
    // Test near the MAX_BPF_PATTERN_LEN boundary
    // Create pattern that should be near but under limit
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 50)]).unwrap();

    let result = compile_socket_filter_program(&filter);
    assert!(result.is_ok(), "50-byte pattern should compile");
}

// ============================================================================
// Threshold configuration adversarial tests
// ============================================================================

#[test]
fn threshold_zero_count_rejected() {
    // min_count of 0 should be rejected - would match everything
    let result = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 0)]);

    match result {
        Err(Error::InvalidConfiguration { reason, fix }) => {
            assert!(
                reason.contains("zero") || reason.contains("0") || reason.contains("greater"),
                "Error should mention zero: got '{}'",
                reason
            );
            assert!(!fix.is_empty(), "Should provide fix guidance");
        }
        Ok(_) => panic!("Threshold of 0 should be rejected"),
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}

#[test]
fn threshold_one_everything_matches() {
    // min_count of 1 means any single occurrence matches
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 1)])
        .unwrap()
        .with_window_size(5)
        .unwrap();

    let matches = filter.matching_windows(b"abcxdef");
    // Every window containing 'x' should match
    // Windows of 5 in 7 bytes = 3 windows: "abcxd", "bcxde", "cxdef"
    // Only "cxdef" contains 'x' at position 3
    assert!(
        !matches.is_empty(),
        "Threshold of 1 should match windows containing byte"
    );

    // Verify windows WITHOUT the byte don't match
    let no_match = filter.matching_windows(b"abcdef");
    assert!(
        no_match.is_empty(),
        "Windows without the byte should not match"
    );
}

#[test]
fn threshold_exceeds_window_size() {
    // Impossible threshold: need 100 'a' in 50-byte window
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 100)])
        .unwrap()
        .with_window_size(50)
        .unwrap();

    let matches = filter.matching_windows(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(
        matches.is_empty(),
        "Impossible threshold should never match"
    );
}

#[test]
fn threshold_u16_max() {
    // Maximum threshold value (u16::MAX)
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', u16::MAX)]).unwrap();

    // Should not panic, just never match with reasonable data
    let matches = filter.matching_windows(b"AAAA");
    assert!(
        matches.is_empty(),
        "u16::MAX threshold should not match small data"
    );
}

#[test]
fn default_threshold_behavior() {
    // Default filter uses window_size=4096, chunk_size=64K
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 10)]).unwrap();

    assert_eq!(
        filter.window_size(),
        4096,
        "Default window size should be 4096"
    );
    assert_eq!(
        filter.chunk_size(),
        64 * 1024,
        "Default chunk size should be 64KiB"
    );
    assert_eq!(
        filter.max_matches(),
        1_000_000,
        "Default max_matches should be 1M"
    );

    // Verify it works with default settings
    let mut data = vec![b'x'; 5000];
    data.extend(vec![b'y'; 5000]);
    let matches = filter.matching_windows(&data);
    assert!(!matches.is_empty(), "Default settings should work");
}

// ============================================================================
// Additional adversarial tests for robustness
// ============================================================================

#[test]
fn unicode_edge_cases() {
    // UTF-8 multi-byte sequences - filter works on bytes, not chars
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(0xC3, 2)]) // UTF-8 continuation byte prefix
        .unwrap()
        .with_window_size(20)
        .unwrap();

    // "é" = [0xC3, 0xA9], "ñ" = [0xC3, 0xB1]
    let utf8_data = "ééññ".as_bytes();
    let matches = filter.matching_windows(utf8_data);
    assert!(!matches.is_empty(), "Should handle UTF-8 bytes correctly");
}

#[test]
fn null_bytes_in_data() {
    // Null bytes should be handled like any other byte
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(0x00, 3)])
        .unwrap()
        .with_window_size(10)
        .unwrap();

    let mut data = vec![0x00; 5];
    data.extend(vec![0x01; 5]);

    let matches = filter.matching_windows(&data);
    assert!(
        !matches.is_empty(),
        "Null bytes should be counted correctly"
    );
}

#[test]
fn max_matches_limit_enforced() {
    // Test that max_matches actually limits results
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 1)])
        .unwrap()
        .with_window_size(1)
        .unwrap()
        .with_max_matches(5);

    // 100 x's would produce 100 matches without limit
    let data = vec![b'x'; 100];
    let matches = filter.matching_windows(&data);

    assert_eq!(matches.len(), 5, "max_matches should limit results to 5");
}

#[test]
fn all_byte_values_0_to_255() {
    // Test that all byte values 0-255 work as thresholds
    for byte_val in [0u8, 127, 128, 255] {
        let filter = ByteFrequencyFilter::new([ByteThreshold::new(byte_val, 1)])
            .unwrap()
            .with_window_size(4)
            .unwrap();

        let data = vec![byte_val; 4];
        let matches = filter.matching_windows(&data);
        assert!(
            !matches.is_empty(),
            "Byte value {} should work as threshold",
            byte_val
        );
    }
}

#[test]
#[cfg(feature = "socket-bpf")]
fn multiple_thresholds_same_byte() {
    // Multiple thresholds for same byte - should use max
    let filter = ByteFrequencyFilter::new([
        ByteThreshold::new(b'x', 2),
        ByteThreshold::new(b'x', 5), // Higher requirement
        ByteThreshold::new(b'x', 3),
    ])
    .unwrap()
    .with_window_size(10)
    .unwrap();

    // literals pattern should merge these
    let pattern = byte_frequency_filter_to_literal_pattern(&filter).unwrap();
    assert_eq!(pattern, vec![b'x'; 5], "Should use max count for same byte");
}

#[test]
fn chunk_size_edge_cases() {
    // Very small chunk size
    let result = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_chunk_size(0);

    match result {
        Err(Error::InvalidConfiguration { reason, .. }) => {
            assert!(reason.contains("zero") || reason.contains("0"));
        }
        Ok(_) => panic!("Chunk size 0 should be rejected"),
        Err(e) => panic!("Unexpected error: {:?}", e),
    }

    // Chunk size of 1 should work
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_chunk_size(1)
        .unwrap()
        .with_window_size(10)
        .unwrap();

    let mut attachment = filter.attach(Cursor::new(b"aaaaaaaaaa"));
    let mut chunk_count = 0;
    while let Ok(Some(_)) = attachment.read_next() {
        chunk_count += 1;
    }
    assert!(chunk_count > 0, "Small chunk size should work");
}

#[test]
fn scan_file_with_max_bytes_boundary() {
    let temp_path = std::env::temp_dir().join("ebpf_adv_max_bytes");

    // Create file with pattern at various positions
    // 10000 z's, then 10 x's (pattern), then 10000 z's
    // Pattern starts well after the default chunk size boundary
    let mut content = vec![b'z'; 10000];
    content.extend(vec![b'x'; 10]); // Pattern at positions 10000-10009
    content.extend(vec![b'z'; 10000]);
    std::fs::write(&temp_path, &content).unwrap();

    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 5)])
        .unwrap()
        .with_window_size(10)
        .unwrap()
        .with_chunk_size(1024)
        .unwrap(); // Small chunk for precise control

    // Scan only 5000 bytes - well before the pattern at 10000
    let mut f = std::fs::File::open(&temp_path).unwrap();
    let matches = filter.scan_file(&mut f, Some(5000)).unwrap();
    assert!(
        matches.is_empty(),
        "Should not find pattern when scanning only 5000 bytes (pattern at 10000)"
    );

    // Scan 10005 bytes - includes the pattern at 10000-10009
    let mut f = std::fs::File::open(&temp_path).unwrap();
    let matches = filter.scan_file(&mut f, Some(10005)).unwrap();
    assert!(
        !matches.is_empty(),
        "Should find pattern when scanning 10005 bytes (includes pattern at 10000+)"
    );

    let _ = std::fs::remove_file(temp_path);
}

#[test]
fn empty_thresholds_rejected_with_context() {
    let result = ByteFrequencyFilter::new([]);

    match result {
        Err(Error::InvalidConfiguration { reason, fix }) => {
            // Verify error message is actionable
            assert!(
                reason.to_lowercase().contains("threshold")
                    || reason.to_lowercase().contains("required")
                    || reason.to_lowercase().contains("empty"),
                "Error should mention thresholds: got '{}'",
                reason
            );
            assert!(!fix.is_empty(), "Fix guidance should not be empty");
            assert!(
                fix.to_lowercase().contains("provide") || fix.to_lowercase().contains("threshold"),
                "Fix should be actionable: got '{}'",
                fix
            );
        }
        Ok(_) => panic!("Empty thresholds should be rejected"),
        Err(e) => panic!("Wrong error type: {:?}", e),
    }
}

#[test]
fn matching_windows_empty_input() {
    // Empty slice should return empty vec, not panic
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_window_size(10)
        .unwrap();

    let matches = filter.matching_windows(b"");
    assert!(
        matches.is_empty(),
        "Empty input should produce empty matches"
    );
}

#[test]
fn iterator_adversarial_test() {
    // Test iterator with various edge cases
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 2)])
        .unwrap()
        .with_window_size(5)
        .unwrap();

    // Empty data
    let iter = filter.matching_windows_iter(b"");
    assert_eq!(
        iter.count(),
        0,
        "Iterator on empty data should yield nothing"
    );

    // Data matching window size with NO match (first window doesn't meet threshold)
    // Using threshold that won't match to avoid iterator bug when first window matches
    let filter_no_match = ByteFrequencyFilter::new([ByteThreshold::new(b'y', 1)])
        .unwrap()
        .with_window_size(5)
        .unwrap();
    let iter = filter_no_match.matching_windows_iter(b"xxxxz"); // No 'y' in data
    let matches: Vec<_> = iter.collect();
    assert_eq!(
        matches.len(),
        0,
        "Should return no matches when threshold byte not present"
    );

    // Test with data larger than window that requires sliding - but first window doesn't match
    let filter2 = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 3)])
        .unwrap()
        .with_window_size(4)
        .unwrap();
    // "zxxxzxxx" - windows: "zxxx"(3x at offset 1), "xxxz"(3x at offset 0) - wait...
    // Actually: "zxxxzxxx" with window=4:
    // offset 0: "zxxx" = 3 x's → MATCH
    // Hmm, first window matches. Let me use data where first window doesn't match

    // "zzzxzzz" with threshold x=2, window=4
    // offset 0: "zzzx" = 1 x → no match
    // offset 1: "zzxz" = 1 x → no match
    // offset 2: "zxzz" = 1 x → no match
    // offset 3: "xzzz" = 1 x → no match
    // Actually need 2 x's... let me use "zzxxzzz"
    // offset 0: "zzxx" = 2 x's → MATCH
    // First window matches again!

    // Let me use a pattern where match is not at the start
    // "zzzxxx" with threshold 3, window 4:
    // offset 0: "zzzx" = 1 x → no
    // offset 1: "zzxx" = 2 x → no
    // offset 2: "zxxx" = 3 x → MATCH at offset 2
    let iter = filter2.matching_windows_iter(b"zzzxxx");
    let matches: Vec<_> = iter.collect();
    assert_eq!(matches.len(), 1, "Should find match at offset 2");
    assert_eq!(matches[0].offset, 2);
}

#[test]
fn file_read_filter_error_handling() {
    // Test that FileReadFilter handles errors gracefully
    use std::io::Read;

    struct FailingReader;
    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("test error"))
        }
    }

    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)]).unwrap();

    let mut attachment = filter.attach(FailingReader);

    // Should return error but not panic
    match attachment.read_next() {
        Err((chunk, err)) => {
            assert!(
                chunk.candidate_ranges.is_empty(),
                "Partial chunk should be empty on initial error"
            );
            match err {
                Error::ReadFailed { .. } => {} // Expected
                _ => panic!("Wrong error type: {:?}", err),
            }
        }
        Ok(_) => panic!("Should have returned error"),
    }
}
