use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};

#[test]
fn test_adv_many_thresholds() {
    let mut thresholds = Vec::new();
    for i in 0..255 {
        thresholds.push(ByteThreshold::new(i as u8, 1));
    }
    
    let filter = ByteFrequencyFilter::new(thresholds).unwrap().with_window_size(255).unwrap();
    let mut data = Vec::new();
    for i in 0..255 {
        data.push(i as u8);
    }
    
    let matches = filter.matching_windows(&data);
    assert_eq!(matches.len(), 1, "Should handle 255 thresholds");
}

#[test]
fn test_adv_max_window_small_data() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)]).unwrap().with_window_size(usize::MAX).unwrap();
    let data = b"a";
    let matches = filter.matching_windows(data);
    assert_eq!(matches.len(), 1, "usize::MAX window on 1 byte data should yield 1 match");
}

#[test]
fn test_adv_chunk_size_1() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'b', 2)])
        .unwrap()
        .with_window_size(5)
        .unwrap()
        .with_chunk_size(1)
        .unwrap();
        
    let data = b"xxbbxx";
    let mut attachment = filter.attach(std::io::Cursor::new(data));
    let mut match_count = 0;
    while let Ok(Some(chunk)) = attachment.read_next() {
        match_count += chunk.candidate_ranges.len();
    }
    assert_eq!(match_count, 4, "Chunk size 1 should correctly stitch together matches");
}
