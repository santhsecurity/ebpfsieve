#[cfg(feature = "socket-bpf")]
use ebpfsieve::kernel;
use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};
use rayon::prelude::*;
use std::io::Cursor;
use std::io::Write;
use std::sync::Arc;
use tempfile::NamedTempFile;

#[test]
#[allow(clippy::unwrap_used)]
fn test_01_threshold_for_every_byte_value() {
    let thresholds: Vec<ByteThreshold> = (0..=255).map(|b| ByteThreshold::new(b, 1)).collect();
    let filter = ByteFrequencyFilter::new(thresholds)
        .unwrap()
        .with_window_size(256)
        .unwrap();
    let data: Vec<u8> = (0..=255).collect();
    let matches = filter.matching_windows(&data);
    assert_eq!(matches.len(), 1);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_02_window_size_1_minimum() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 1)])
        .unwrap()
        .with_window_size(1)
        .unwrap();
    let matches = filter.matching_windows(b"A");
    assert_eq!(matches.len(), 1);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_03_window_size_1gb_absurd() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 1)])
        .unwrap()
        .with_window_size(1_000_000_000)
        .unwrap();
    let matches = filter.matching_windows(b"A");
    assert_eq!(matches.len(), 1);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_04_chunk_size_1() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 1)])
        .unwrap()
        .with_chunk_size(1)
        .unwrap()
        .with_window_size(2)
        .unwrap();
    let mut attachment = filter.attach(Cursor::new(b"AA"));
    let mut count = 0;
    while let Ok(Some(chunk)) = attachment.read_next() {
        count += chunk.candidate_ranges.len();
    }
    assert_eq!(count, 2);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_05_filter_rejects_all_input() {
    let thresholds: Vec<ByteThreshold> = (0..=255).map(|b| ByteThreshold::new(b, 255)).collect();
    let filter = ByteFrequencyFilter::new(thresholds)
        .unwrap()
        .with_window_size(65535)
        .unwrap();
    let matches = filter.matching_windows(b"Hello world");
    assert_eq!(matches.len(), 0);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_06_filter_accepts_all_input() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 1)])
        .unwrap()
        .with_window_size(1)
        .unwrap();
    let matches = filter.matching_windows(b"AAAAAAAAAAAAAAAA");
    assert_eq!(matches.len(), 16);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_07_concurrent_filter_8_threads() {
    let filter = Arc::new(
        ByteFrequencyFilter::new([ByteThreshold::new(b'A', 2)])
            .unwrap()
            .with_window_size(5)
            .unwrap(),
    );
    let data: Vec<u8> = vec![b'A'; 1000];
    (0..8).into_par_iter().for_each(|_| {
        let matches = filter.matching_windows(&data);
        assert_eq!(matches.len(), 996);
    });
}

#[test]
#[allow(clippy::unwrap_used)]
#[cfg(feature = "socket-bpf")]
fn test_08_ebpf_compilation_extreme_filters() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 255)]).unwrap();
    let insns = kernel::compile_socket_filter_program(&filter).unwrap();
    assert!(!insns.is_empty());
}
#[test]
#[allow(clippy::unwrap_used)]
fn test_09_scan_file_all_identical_bytes() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 4)])
        .unwrap()
        .with_window_size(4)
        .unwrap();
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&[b'A'; 100]).unwrap();
    let mut file = tmp.reopen().unwrap();
    let matches = filter.scan_file(&mut file, None).unwrap();
    assert_eq!(matches.len(), 97);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_10_max_matches_0() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 1)])
        .unwrap()
        .with_max_matches(0);
    let matches = filter.matching_windows(b"AAAA");
    assert_eq!(matches.len(), 0);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_11_max_matches_usize_max() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 1)])
        .unwrap()
        .with_max_matches(usize::MAX);
    let matches = filter.matching_windows(b"AAAA");
    assert_eq!(matches.len(), 1);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_12_all_null_bytes() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(0, 1)])
        .unwrap()
        .with_window_size(1)
        .unwrap();
    let matches = filter.matching_windows(b"\0\0\0");
    assert_eq!(matches.len(), 3);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_13_max_threshold_count_u16_max() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', u16::MAX)])
        .unwrap()
        .with_window_size(usize::MAX)
        .unwrap();
    let matches = filter.matching_windows(b"A");
    assert_eq!(matches.len(), 0);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_14_all_thresholds_u16_max() {
    let thresholds: Vec<ByteThreshold> =
        (0..=255).map(|b| ByteThreshold::new(b, u16::MAX)).collect();
    let filter = ByteFrequencyFilter::new(thresholds)
        .unwrap()
        .with_window_size(usize::MAX)
        .unwrap();
    let matches = filter.matching_windows(b"A");
    assert_eq!(matches.len(), 0);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_15_chunk_size_usize_max() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 1)])
        .unwrap()
        .with_chunk_size(usize::MAX)
        .unwrap();
    let matches = filter.matching_windows(b"A");
    assert_eq!(matches.len(), 1);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_16_window_size_larger_than_data() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 1)])
        .unwrap()
        .with_window_size(10)
        .unwrap();
    let matches = filter.matching_windows(b"A");
    assert_eq!(matches.len(), 1);
}
#[test]
#[allow(clippy::unwrap_used)]
fn test_17_window_size_larger_than_chunk_size() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 1)])
        .unwrap()
        .with_window_size(10)
        .unwrap()
        .with_chunk_size(2)
        .unwrap();
    let mut attachment = filter.attach(Cursor::new(b"A"));
    let chunk = attachment.read_next().unwrap().unwrap();
    assert_eq!(chunk.candidate_ranges.len(), 1);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_18_empty_data() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 1)]).unwrap();
    let matches = filter.matching_windows(b"");
    assert_eq!(matches.len(), 0);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_19_one_byte_data_match() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 1)])
        .unwrap()
        .with_window_size(1)
        .unwrap();
    let matches = filter.matching_windows(b"A");
    assert_eq!(matches.len(), 1);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_20_one_byte_data_no_match() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'B', 1)])
        .unwrap()
        .with_window_size(1)
        .unwrap();
    let matches = filter.matching_windows(b"A");
    assert_eq!(matches.len(), 0);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_21_scan_file_with_max_bytes_0() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 1)]).unwrap();
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(b"A").unwrap();
    let mut file = tmp.reopen().unwrap();
    let matches = filter.scan_file(&mut file, Some(0)).unwrap();
    assert_eq!(matches.len(), 0);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_22_scan_file_with_max_bytes_1() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 1)])
        .unwrap()
        .with_chunk_size(1)
        .unwrap()
        .with_window_size(1)
        .unwrap();
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(b"AA").unwrap();
    let mut file = tmp.reopen().unwrap();
    let matches = filter.scan_file(&mut file, Some(1)).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_23_scan_file_with_max_bytes_u64_max() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 1)]).unwrap();
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(b"A").unwrap();
    let mut file = tmp.reopen().unwrap();
    let matches = filter.scan_file(&mut file, Some(u64::MAX)).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_24_iterator_extreme_slide() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 1)])
        .unwrap()
        .with_window_size(1)
        .unwrap();
    let data = vec![b'A'; 1000];
    let matches: Vec<_> = filter.matching_windows_iter(&data).collect();
    assert_eq!(matches.len(), 1000);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_25_multiple_thresholds_same_byte_increasing() {
    let filter =
        ByteFrequencyFilter::new([ByteThreshold::new(b'A', 1), ByteThreshold::new(b'A', 2)])
            .unwrap()
            .with_window_size(2)
            .unwrap();
    let matches = filter.matching_windows(b"AA");
    assert_eq!(matches.len(), 1);
}
#[test]
#[allow(clippy::unwrap_used)]
fn test_26_multiple_thresholds_same_byte_decreasing() {
    let filter =
        ByteFrequencyFilter::new([ByteThreshold::new(b'A', 2), ByteThreshold::new(b'A', 1)])
            .unwrap()
            .with_window_size(2)
            .unwrap();
    let matches = filter.matching_windows(b"AA");
    assert_eq!(matches.len(), 1);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_27_pattern_overlap_exact_window() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 2)])
        .unwrap()
        .with_window_size(2)
        .unwrap();
    let matches = filter.matching_windows(b"AAA");
    assert_eq!(matches.len(), 2);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_28_matches_bytes_exact() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 1)]).unwrap();
    assert!(filter.matches_bytes(b"A"));
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_29_matches_bytes_less() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 2)]).unwrap();
    assert!(!filter.matches_bytes(b"A"));
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_30_attachment_cross_chunk_extreme() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 2)])
        .unwrap()
        .with_chunk_size(1)
        .unwrap()
        .with_window_size(2)
        .unwrap();
    let mut attachment = filter.attach(Cursor::new(b"AA"));
    let mut count = 0;
    while let Ok(Some(chunk)) = attachment.read_next() {
        count += chunk.candidate_ranges.len();
    }
    assert_eq!(count, 1);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_31_iterator_exhaustion() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 1)])
        .unwrap()
        .with_window_size(1)
        .unwrap();
    let mut iter = filter.matching_windows_iter(b"A");
    assert!(iter.next().is_some());
    assert!(iter.next().is_none());
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_32_max_matches_truncation() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 1)])
        .unwrap()
        .with_max_matches(2)
        .with_window_size(1)
        .unwrap();
    let matches = filter.matching_windows(b"AAA");
    assert_eq!(matches.len(), 2);
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_33_threshold_zero_count() {
    let res = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 0)]);
    assert!(res.is_err());
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_34_iterator_zero_length() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 1)])
        .unwrap()
        .with_window_size(1)
        .unwrap();
    let iter = filter.matching_windows_iter(b"");
    assert_eq!(iter.count(), 0);
}
