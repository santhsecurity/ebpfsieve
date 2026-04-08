#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]
//! Iterator correctness tests for MatchWindowIter.
//!
//! These tests are designed to catch off-by-one errors and edge cases
//! in the lazy window iterator.

use ebpfsieve::{ByteFrequencyFilter, ByteThreshold, MatchWindow};

#[test]
fn iterator_first_window_match_does_not_panic() {
    // Regression test: if the first window matched, the old code returned
    // without advancing pos, causing a subtract-with-overflow on the next
    // call to next().
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_window_size(3)
        .unwrap();

    let mut iter = filter.matching_windows_iter(b"aaa");
    assert_eq!(
        iter.next(),
        Some(MatchWindow {
            offset: 0,
            length: 3
        })
    );
    // This second call used to panic:
    assert!(iter.next().is_none());
}

#[test]
fn iterator_empty_input_yields_nothing() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_window_size(3)
        .unwrap();

    let mut iter = filter.matching_windows_iter(b"");
    assert!(iter.next().is_none());
}

#[test]
fn iterator_window_larger_than_input_clamps() {
    // When the input is shorter than the window size, the iterator clamps
    // the window to the input length and evaluates thresholds against that.
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_window_size(10)
        .unwrap();

    let mut iter = filter.matching_windows_iter(b"aa");
    // Window is clamped to 2, threshold a>=1 is met.
    assert_eq!(
        iter.next(),
        Some(MatchWindow {
            offset: 0,
            length: 2
        })
    );
    assert!(iter.next().is_none());
}

#[test]
fn iterator_single_byte_window() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_window_size(1)
        .unwrap();

    let mut iter = filter.matching_windows_iter(b"aba");
    assert_eq!(
        iter.next(),
        Some(MatchWindow {
            offset: 0,
            length: 1
        })
    );
    assert_eq!(
        iter.next(),
        Some(MatchWindow {
            offset: 2,
            length: 1
        })
    );
    assert!(iter.next().is_none());
}

#[test]
fn iterator_matches_vec_equivalence() {
    let filter =
        ByteFrequencyFilter::new([ByteThreshold::new(b'e', 2), ByteThreshold::new(b'r', 2)])
            .unwrap()
            .with_window_size(5)
            .unwrap();

    let bytes = b"xxerrerxx";
    let from_vec = filter.matching_windows(bytes);
    let from_iter: Vec<_> = filter.matching_windows_iter(bytes).collect();
    assert_eq!(from_vec, from_iter);
}

#[test]
fn iterator_no_match_returns_none() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'z', 5)])
        .unwrap()
        .with_window_size(4)
        .unwrap();

    let mut iter = filter.matching_windows_iter(b"abcabcabc");
    assert!(iter.next().is_none());
}

#[test]
fn iterator_every_window_matches() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_window_size(2)
        .unwrap();

    let bytes = b"aaa";
    let mut iter = filter.matching_windows_iter(bytes);
    assert_eq!(
        iter.next(),
        Some(MatchWindow {
            offset: 0,
            length: 2
        })
    );
    assert_eq!(
        iter.next(),
        Some(MatchWindow {
            offset: 1,
            length: 2
        })
    );
    assert!(iter.next().is_none());
}

#[test]
fn iterator_adversarial_byte_flood() {
    // Ensure saturating arithmetic doesn't break the histogram.
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(0xFF, 1)])
        .unwrap()
        .with_window_size(65536)
        .unwrap();

    let bytes = vec![0xFF; 131_072];
    let collected: Vec<_> = filter.matching_windows_iter(&bytes).collect();
    // Every window of 65536 should match.
    assert_eq!(collected.len(), 65537);
    assert_eq!(collected[0].offset, 0);
    assert_eq!(collected[collected.len() - 1].offset, 65536);
}
