use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5000))]

    #[test]
    fn prop_filter_invariants(
        data in prop::collection::vec(any::<u8>(), 0..1024),
        w_size in 1..2048usize,
        t_val in 1..255u16,
        b_val in any::<u8>()
    ) {
        let filter = ByteFrequencyFilter::new([ByteThreshold::new(b_val, t_val)])
            .unwrap()
            .with_window_size(w_size)
            .unwrap();

        let matches = filter.matching_windows(&data);

        for m in matches {
            let start = m.offset as usize;
            let end = start + m.length;
            let window = &data[start..end];
            let count = window.iter().filter(|&&b| b == b_val).count();
            assert!(count >= t_val as usize, "Invalid match found!");
        }
    }

    #[test]
    fn prop_multiple_thresholds(
        data in prop::collection::vec(any::<u8>(), 0..1024),
        w_size in 1..2048usize,
        t1 in 1..10u16, b1 in any::<u8>(),
        t2 in 1..10u16, b2 in any::<u8>()
    ) {
        let filter = ByteFrequencyFilter::new([
            ByteThreshold::new(b1, t1),
            ByteThreshold::new(b2, t2)
        ]).unwrap().with_window_size(w_size).unwrap();

        let matches = filter.matching_windows(&data);

        for m in matches {
            let start = m.offset as usize;
            let end = start + m.length;
            let window = &data[start..end];

            let count1 = window.iter().filter(|&&b| b == b1).count();
            let count2 = window.iter().filter(|&&b| b == b2).count();

            assert!(count1 >= t1 as usize, "First threshold failed");
            assert!(count2 >= t2 as usize, "Second threshold failed");
        }
    }
}
