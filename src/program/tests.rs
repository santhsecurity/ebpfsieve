use super::*;
use crate::map::{ByteThreshold, MatchWindow};
use std::io::Cursor;

#[test]
fn test_byte_threshold_new() {
    let t = ByteThreshold::new(b'x', 42);
    assert_eq!(t.byte, b'x');
    assert_eq!(t.min_count, 42);
}

#[test]
fn test_filter_getters() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_window_size(1024)
        .unwrap()
        .with_chunk_size(2048)
        .unwrap();

    assert_eq!(filter.thresholds(), &[ByteThreshold::new(b'a', 1)]);
    assert_eq!(filter.window_size(), 1024);
    assert_eq!(filter.chunk_size(), 2048);
    assert_eq!(filter.max_matches(), 1_000_000);
}

#[test]
fn test_zero_window_size_is_rejected() {
    let result = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_window_size(0);
    assert!(result.is_err());
}

#[test]
fn test_zero_chunk_size_is_rejected() {
    let result = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_chunk_size(0);
    assert!(result.is_err());
}

#[test]
fn test_max_matches_limit() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_window_size(1)
        .unwrap()
        .with_max_matches(5);

    // "aaaaa" has 5 'a's, each as a window of size 1
    let matches = filter.matching_windows(b"aaaaa");
    assert_eq!(matches.len(), 5);

    // Same data but with max_matches=3
    let filter_limited = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_window_size(1)
        .unwrap()
        .with_max_matches(3);
    let matches_limited = filter_limited.matching_windows(b"aaaaa");
    assert_eq!(matches_limited.len(), 3);
}

#[test]
fn test_matches_bytes() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 2)]).unwrap();
    assert!(filter.matches_bytes(b"aab"));
    assert!(!filter.matches_bytes(b"ab"));
}

#[test]
fn matching_windows_slide_correctly() {
    let filter =
        ByteFrequencyFilter::new([ByteThreshold::new(b'e', 2), ByteThreshold::new(b'r', 2)])
            .unwrap()
            .with_window_size(5)
            .unwrap();

    // "xxerrerxx" with window=5, needs e≥2 AND r≥2:
    // offset 1: "xerre" → x=1,e=2,r=2 → MATCH
    // offset 2: "errer" → e=2,r=2 → MATCH
    // offset 3: "rrerx" → r=2,e=1 → no (e<2)
    let matches = filter.matching_windows(b"xxerrerxx");
    assert_eq!(
        matches,
        vec![
            MatchWindow {
                offset: 1,
                length: 5
            },
            MatchWindow {
                offset: 2,
                length: 5
            },
        ]
    );
}

#[test]
fn attachment_reports_cross_chunk_match() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 2)])
        .unwrap()
        .with_window_size(3)
        .unwrap()
        .with_chunk_size(2)
        .unwrap();
    let mut attachment = filter.clone().attach(Cursor::new(b"baac".to_vec()));
    assert_eq!(attachment.filter(), &filter);

    let first = match attachment.read_next() {
        Ok(Some(chunk)) => chunk,
        Ok(None) => panic!("expected first chunk"),
        Err((_, e)) => panic!("unexpected error: {:?}", e),
    };
    assert!(first.candidate_ranges.is_empty());

    // "baac" with chunk=2, window=3, needs a≥2:
    // Chunk 2 combines carry "ba" + new "ac" = "baac"
    // Window "baa" at offset 0: a=2 → MATCH (spans carry into new data)
    // Window "aac" at offset 1: a=2 → MATCH
    let second = match attachment.read_next() {
        Ok(Some(chunk)) => chunk,
        Ok(None) => panic!("expected second chunk"),
        Err((_, e)) => panic!("unexpected error: {:?}", e),
    };
    assert_eq!(
        second.candidate_ranges,
        vec![
            MatchWindow {
                offset: 0,
                length: 3
            },
            MatchWindow {
                offset: 1,
                length: 3
            },
        ]
    );
}

#[test]
fn empty_thresholds_are_rejected() {
    assert!(ByteFrequencyFilter::new([]).is_err());
}

#[test]
fn zero_count_thresholds_are_rejected() {
    assert!(ByteFrequencyFilter::new([ByteThreshold::new(b'a', 0)]).is_err());
}

#[test]
fn test_scan_file_and_path() {
    let temp_path = std::env::temp_dir().join("ebpfsieve_test_file.txt");
    std::fs::write(&temp_path, b"xxerrerxx").unwrap();

    let filter =
        ByteFrequencyFilter::new([ByteThreshold::new(b'e', 2), ByteThreshold::new(b'r', 2)])
            .unwrap()
            .with_window_size(5)
            .unwrap()
            .with_chunk_size(4)
            .unwrap();

    let mut f = std::fs::File::open(&temp_path).unwrap();
    let matches = filter.scan_file(&mut f, None).unwrap();
    assert_eq!(
        matches,
        vec![
            MatchWindow {
                offset: 1,
                length: 5
            },
            MatchWindow {
                offset: 2,
                length: 5
            },
        ]
    );

    let path_matches = filter.scan_path(&temp_path, None).unwrap();
    assert_eq!(path_matches, matches);

    let _ = std::fs::remove_file(temp_path);
}

#[test]
fn test_scan_file_with_max_bytes() {
    let temp_path = std::env::temp_dir().join("ebpfsieve_test_max_bytes.txt");
    // Write padding, then a unique pattern ("aaabbb"), then more padding
    // Filter requires 3 'a's and 3 'b's in a 6-byte window
    let mut content = vec![b'x'; 100];
    content.extend_from_slice(b"aaabbb"); // Unique pattern at offset 100
    content.extend_from_slice(&[b'x'; 100]);
    std::fs::write(&temp_path, &content).unwrap();

    let filter =
        ByteFrequencyFilter::new([ByteThreshold::new(b'a', 3), ByteThreshold::new(b'b', 3)])
            .unwrap()
            .with_window_size(6)
            .unwrap()
            .with_chunk_size(64)
            .unwrap();

    // Scan only first 50 bytes - should not reach the pattern at offset 100
    let mut f = std::fs::File::open(&temp_path).unwrap();
    let matches = filter.scan_file(&mut f, Some(50)).unwrap();
    assert_eq!(
        matches.len(),
        0,
        "Expected 0 matches when scanning 50 bytes"
    );

    // Scan first 110 bytes - should find the pattern at offset 100
    let mut f = std::fs::File::open(&temp_path).unwrap();
    let matches = filter.scan_file(&mut f, Some(110)).unwrap();
    assert_eq!(matches.len(), 1, "Expected 1 match when scanning 110 bytes");
    assert_eq!(matches[0].offset, 100);

    let _ = std::fs::remove_file(temp_path);
}

#[test]
fn test_matching_windows_iter() {
    let filter =
        ByteFrequencyFilter::new([ByteThreshold::new(b'e', 2), ByteThreshold::new(b'r', 2)])
            .unwrap()
            .with_window_size(5)
            .unwrap();

    let iter = filter.matching_windows_iter(b"xxerrerxx");
    let matches: Vec<_> = iter.collect();
    assert_eq!(
        matches,
        vec![
            MatchWindow {
                offset: 1,
                length: 5
            },
            MatchWindow {
                offset: 2,
                length: 5
            },
        ]
    );
}

#[test]
fn matching_windows_iter_respects_max_matches() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_window_size(1)
        .unwrap()
        .with_max_matches(2);
    let count = filter.matching_windows_iter(b"aaaa").count();
    assert_eq!(count, 2);
}
