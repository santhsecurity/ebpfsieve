use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn test_prop_fuzz_sliding_window(
        data in prop::collection::vec(any::<u8>(), 0..2048),
        window_size in 1..4096usize,
        t1_byte in any::<u8>(),
        t1_count in 1..255u16,
        t2_byte in any::<u8>(),
        t2_count in 1..255u16,
    ) {
        if let Ok(filter) = ByteFrequencyFilter::new([
            ByteThreshold::new(t1_byte, t1_count),
            ByteThreshold::new(t2_byte, t2_count)
        ]) {
            if let Ok(filter) = filter.with_window_size(window_size) {
                let matches = filter.matching_windows(&data);
                for m in matches {
                    let w = &data[m.offset as usize..(m.offset as usize + m.length)];
                    let c1 = w.iter().filter(|&&b| b == t1_byte).count();
                    let c2 = w.iter().filter(|&&b| b == t2_byte).count();
                    assert!(c1 >= t1_count as usize, "Match condition 1 failed");
                    assert!(c2 >= t2_count as usize, "Match condition 2 failed");
                }
            }
        }
    }
}
