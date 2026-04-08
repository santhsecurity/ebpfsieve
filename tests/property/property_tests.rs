use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_shifting_data_retains_matches(
        data in prop::collection::vec(any::<u8>(), 100..200),
        shift in 1..50usize
    ) {
        let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'A', 2)]).unwrap().with_window_size(10).unwrap();
        
        let matches1 = filter.matching_windows(&data);
        
        let mut shifted_data = vec![b'B'; shift];
        shifted_data.extend(&data);
        
        let matches2 = filter.matching_windows(&shifted_data);
        
        for m1 in matches1 {
            let found = matches2.iter().any(|m2| m2.offset == m1.offset + shift as u64);
            assert!(found, "Match lost after shifting data");
        }
    }
    
    #[test]
    fn test_increasing_threshold_decreases_matches(
        data in prop::collection::vec(any::<u8>(), 500..1000),
        t1 in 1..10u8,
        t2 in 11..20u8
    ) {
        let filter1 = ByteFrequencyFilter::new([ByteThreshold::new(b'Z', t1 as u16)]).unwrap().with_window_size(50).unwrap();
        let filter2 = ByteFrequencyFilter::new([ByteThreshold::new(b'Z', t2 as u16)]).unwrap().with_window_size(50).unwrap();
        
        let matches1 = filter1.matching_windows(&data);
        let matches2 = filter2.matching_windows(&data);
        
        assert!(matches1.len() >= matches2.len(), "A stricter threshold should never yield more matches");
    }
    
    #[test]
    fn test_increasing_window_size_increases_matches(
        data in prop::collection::vec(any::<u8>(), 500..1000),
        w1 in 10..50usize,
        w2 in 60..100usize
    ) {
        let filter1 = ByteFrequencyFilter::new([ByteThreshold::new(b'Q', 2)]).unwrap().with_window_size(w1).unwrap();
        let filter2 = ByteFrequencyFilter::new([ByteThreshold::new(b'Q', 2)]).unwrap().with_window_size(w2).unwrap();
        
        let matches1 = filter1.matching_windows(&data);
        let matches2 = filter2.matching_windows(&data);
        
        if !matches1.is_empty() {
            assert!(!matches2.is_empty(), "If a small window matches, a larger one must also match somewhere");
        }
    }
    
    #[test]
    fn test_filter_equality_invariance(
        data in prop::collection::vec(any::<u8>(), 100..200),
        b1 in any::<u8>(),
        b2 in any::<u8>()
    ) {
        let filter1 = ByteFrequencyFilter::new([
            ByteThreshold::new(b1, 1),
            ByteThreshold::new(b2, 1)
        ]).unwrap().with_window_size(10).unwrap();
        
        let filter2 = ByteFrequencyFilter::new([
            ByteThreshold::new(b2, 1),
            ByteThreshold::new(b1, 1)
        ]).unwrap().with_window_size(10).unwrap();
        
        let matches1 = filter1.matching_windows(&data);
        let matches2 = filter2.matching_windows(&data);
        
        assert_eq!(matches1, matches2, "Filter behavior must be independent of threshold order");
    }
    
    #[test]
    fn test_reverse_data_invariance(
        data in prop::collection::vec(any::<u8>(), 100..200)
    ) {
        let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'R', 2)]).unwrap().with_window_size(15).unwrap();
        
        let mut reversed_data = data.clone();
        reversed_data.reverse();
        
        let matches1 = filter.matching_windows(&data);
        let matches2 = filter.matching_windows(&reversed_data);
        
        assert_eq!(matches1.len(), matches2.len(), "Total match count must be invariant under reversal");
    }
    
    #[test]
    fn test_duplicate_data_doubles_matches_roughly(
        data in prop::collection::vec(any::<u8>(), 500..1000)
    ) {
        let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'W', 1)]).unwrap().with_window_size(10).unwrap();
        
        let matches1 = filter.matching_windows(&data);
        
        let mut doubled_data = data.clone();
        doubled_data.extend(&data);
        let matches2 = filter.matching_windows(&doubled_data);
        
        assert!(matches2.len() >= matches1.len() * 2, "Doubling data should at least double the matches");
    }
    
    #[test]
    fn test_chunk_size_invariance(
        data in prop::collection::vec(any::<u8>(), 500..1000),
        c1 in 1..50usize,
        c2 in 100..500usize
    ) {
        let filter1 = ByteFrequencyFilter::new([ByteThreshold::new(b'K', 1)])
            .unwrap()
            .with_window_size(10)
            .unwrap()
            .with_chunk_size(c1)
            .unwrap();
            
        let filter2 = ByteFrequencyFilter::new([ByteThreshold::new(b'K', 1)])
            .unwrap()
            .with_window_size(10)
            .unwrap()
            .with_chunk_size(c2)
            .unwrap();
            
        let mut matches1 = Vec::new();
        let mut attachment1 = filter1.attach(std::io::Cursor::new(data.clone()));
        while let Ok(Some(chunk)) = attachment1.read_next() {
            matches1.extend(chunk.candidate_ranges);
        }
        
        let mut matches2 = Vec::new();
        let mut attachment2 = filter2.attach(std::io::Cursor::new(data.clone()));
        while let Ok(Some(chunk)) = attachment2.read_next() {
            matches2.extend(chunk.candidate_ranges);
        }
        
        assert_eq!(matches1.len(), matches2.len(), "Total match count should be invariant to chunk size");
    }
    
    #[test]
    fn test_offset_invariance(
        data in prop::collection::vec(any::<u8>(), 100..200),
        pad_len in 1..50usize,
        pad_byte in any::<u8>()
    ) {
        let track_byte = if pad_byte == 255 { 0 } else { pad_byte + 1 };
        
        let filter = ByteFrequencyFilter::new([ByteThreshold::new(track_byte, 1)])
            .unwrap()
            .with_window_size(10)
            .unwrap();
            
        let matches_orig = filter.matching_windows(&data);
        
        let mut padded_data = vec![pad_byte; pad_len];
        padded_data.extend(&data);
        
        let matches_padded = filter.matching_windows(&padded_data);
        
        for m in matches_orig {
            let found = matches_padded.iter().any(|pm| pm.offset == m.offset + pad_len as u64);
            assert!(found, "Original match at offset {} should exist at offset {} in padded data", m.offset, m.offset + pad_len as u64);
        }
    }
}
