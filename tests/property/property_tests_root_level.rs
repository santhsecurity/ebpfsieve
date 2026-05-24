#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]
use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_property_matches_no_false_positives(
        data in prop::collection::vec(any::<u8>(), 0..2048),
        threshold in 1..255u8
    ) {
        let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', threshold as u16)]).unwrap().with_window_size(100).unwrap();
        let matches = filter.matching_windows(&data);
        for m in matches {
            let window = &data[m.offset as usize..(m.offset as usize + m.length)];
            let count = window.iter().filter(|&&b| b == b'x').count();
            assert!(count >= threshold as usize, "False positive found!");
        }
    }
}
