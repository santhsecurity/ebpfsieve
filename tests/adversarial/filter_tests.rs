use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_large_input_fuzzing(
        data in prop::collection::vec(any::<u8>(), 0..10_000),
        window_size in 1..2000usize
    ) {
        let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 1)]).unwrap().with_window_size(window_size).unwrap();
        let matches = filter.matching_windows(&data);
        for m in matches {
            let window = &data[m.offset as usize..(m.offset as usize + m.length)];
            let count = window.iter().filter(|&&b| b == b'x').count();
            assert!(count >= 1, "Match found but property violated");
        }
    }
}
