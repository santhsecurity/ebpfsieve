#![no_main]
use libfuzzer_sys::fuzz_target;
use ebpfsieve::ByteFrequencyFilter;

fuzz_target!(|data: &[u8]| {
    // Fuzz the full filter construction + scan pipeline
    if data.len() < 4 { return; }

    // Build thresholds from first bytes
    let num_thresholds = (data[0] as usize % 4) + 1;
    let mut thresholds = Vec::new();
    for i in 0..num_thresholds {
        let idx = 1 + i * 2;
        if idx + 1 >= data.len() { break; }
        let byte = data[idx];
        let count = (data[idx + 1] as u16).max(1);
        thresholds.push(ebpfsieve::ByteThreshold::new(byte, count));
    }

    if thresholds.is_empty() { return; }

    let offset = 1 + num_thresholds * 2;
    let input = if offset < data.len() { &data[offset..] } else { &[] };

    if let Ok(filter) = ByteFrequencyFilter::new(thresholds) {
        let windows = filter.matching_windows(input);
        // Verify: all window offsets are within input bounds
        for w in &windows {
            assert!(w.offset as usize + w.length <= input.len());
        }
    }
});
