#![allow(clippy::unwrap_used, clippy::expect_used)]

//! S-perf-pmg: byte-frequency filter edge catalog.

use ebpfsieve::{ByteFrequencyFilter, ByteThreshold, Error, MatchWindow};

#[test]
fn edge_filter_single_threshold() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 2)]).unwrap();
    let w = f.matching_windows(b"xaaay");
    assert_eq!(w, vec![MatchWindow { offset: 0, length: 5 }]);
}

#[test]
fn edge_filter_empty_input() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 1)]).unwrap();
    assert!(f.matching_windows(b"").is_empty());
}

#[test]
fn edge_filter_no_match() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(b'z', 5)]).unwrap();
    assert!(f.matching_windows(b"hello").is_empty());
}

#[test]
fn edge_window_size_one() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_window_size(1)
        .unwrap();
    assert_eq!(f.matching_windows(b"a").len(), 1);
}

#[test]
fn edge_window_size_zero_errors() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)]).unwrap();
    assert!(matches!(
        f.with_window_size(0),
        Err(Error::InvalidConfiguration { .. })
    ));
}

#[test]
fn edge_threshold_min_count_one() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(b'!', 1)]).unwrap();
    assert!(!f.matching_windows(b"!").is_empty());
}

#[test]
fn edge_multiple_thresholds_and() {
    let f = ByteFrequencyFilter::new([
        ByteThreshold::new(b'a', 2),
        ByteThreshold::new(b'b', 1),
    ])
    .unwrap();
    let w = f.matching_windows(b"xxaabb");
    assert!(!w.is_empty());
}

#[test]
fn edge_match_at_offset_zero() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(b's', 2)]).unwrap();
    let w = f.matching_windows(b"ssend");
    assert_eq!(w[0].offset, 0);
}

#[test]
fn edge_all_bytes_threshold() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(0, 1)]).unwrap();
    let _ = f.matching_windows(&[0u8]);
}

#[test]
fn edge_high_byte_threshold() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(255, 1)]).unwrap();
    assert!(!f.matching_windows(&[255, 255]).is_empty());
}

#[test]
fn edge_window_exact_fit() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 3)])
        .unwrap()
        .with_window_size(3)
        .unwrap();
    assert_eq!(f.matching_windows(b"xxx").len(), 1);
}

#[test]
fn edge_sliding_multiple_windows() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 2)])
        .unwrap()
        .with_window_size(3)
        .unwrap();
    let w = f.matching_windows(b"aaa");
    assert!(w.len() >= 1);
}

#[test]
fn edge_empty_threshold_list_errors() {
    assert!(ByteFrequencyFilter::new([]).is_err());
}

#[test]
fn edge_threshold_zero_count_rejected() {
    assert!(ByteFrequencyFilter::new([ByteThreshold::new(b'a', 0)]).is_err());
}

#[test]
fn edge_unicode_bytes() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(b'\xC3', 1)]).unwrap();
    let _ = f.matching_windows("é".as_bytes());
}

#[test]
fn edge_long_input_stream() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(b'q', 2)]).unwrap();
    let data = vec![b'q'; 10_000];
    let w = f.matching_windows(&data);
    assert!(!w.is_empty());
}

#[test]
fn edge_window_larger_than_input_clamps_to_len() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_window_size(100)
        .unwrap();
    let w = f.matching_windows(b"a");
    assert_eq!(w, vec![MatchWindow { offset: 0, length: 1 }]);
}

#[test]
fn edge_match_window_length_positive() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(b'b', 2)]).unwrap();
    for w in f.matching_windows(b"abbb") {
        assert!(w.length > 0);
    }
}

#[test]
fn edge_two_thresholds_unsatisfiable() {
    let f = ByteFrequencyFilter::new([
        ByteThreshold::new(b'a', 10),
        ByteThreshold::new(b'b', 10),
    ])
    .unwrap();
    assert!(f.matching_windows(b"short").is_empty());
}

#[test]
fn edge_repeated_filter_calls() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(b'c', 2)]).unwrap();
    let a = f.matching_windows(b"ccx");
    let b = f.matching_windows(b"ccx");
    assert_eq!(a, b);
}

#[test]
fn edge_byte_threshold_const() {
    let t = ByteThreshold::new(b'k', 4);
    assert_eq!(t.byte, b'k');
    assert_eq!(t.min_count, 4);
}

#[test]
fn edge_filter_clone_thresholds() {
    let f1 = ByteFrequencyFilter::new([ByteThreshold::new(b'd', 1)]).unwrap();
    let f2 = ByteFrequencyFilter::new([ByteThreshold::new(b'd', 1)]).unwrap();
    assert_eq!(f1.matching_windows(b"d"), f2.matching_windows(b"d"));
}

#[test]
fn edge_single_byte_input_no_match() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(b'z', 2)]).unwrap();
    assert!(f.matching_windows(b"x").is_empty());
}

#[test]
fn edge_window_size_equals_min_counts_sum() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 2), ByteThreshold::new(b'b', 1)])
        .unwrap()
        .with_window_size(3)
        .unwrap();
    assert!(!f.matching_windows(b"aab").is_empty());
}

#[test]
fn edge_match_at_end() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(b'z', 2)]).unwrap();
    let w = f.matching_windows(b"xxzz");
    assert!(!w.is_empty());
}

#[test]
fn edge_alternating_pattern() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(b'1', 2)]).unwrap();
    let data = b"0101010111";
    let _ = f.matching_windows(data);
}

#[test]
fn edge_max_threshold_count_u16() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(b'm', u16::MAX)]).unwrap();
    assert!(f.matching_windows(b"m").is_empty());
}

#[test]
fn edge_all_zeros_input() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(0, 3)]).unwrap();
    let w = f.matching_windows(&[0, 0, 0, 0]);
    assert!(!w.is_empty());
}

#[test]
fn edge_disjoint_matches() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 2)])
        .unwrap()
        .with_window_size(2)
        .unwrap();
    let _ = f.matching_windows(b"xx yy xx");
}

#[test]
fn edge_filter_with_window_on_empty_after_build() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)]).unwrap();
    let f = f.with_window_size(4).unwrap();
    assert!(f.matching_windows(b"").is_empty());
}

#[test]
fn edge_threshold_byte_boundary_254() {
    let f = ByteFrequencyFilter::new([ByteThreshold::new(254, 1)]).unwrap();
    assert!(!f.matching_windows(&[254]).is_empty());
}

#[test]
fn edge_match_windows_in_bounds() {
    let input = b"abcabcabc";
    let f = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 2)]).unwrap();
    for w in f.matching_windows(input) {
        assert!(w.offset as usize + w.length <= input.len());
    }
}
