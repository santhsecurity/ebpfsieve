#![no_main]

use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let n = (data[0] as usize % 3) + 1;
    let mut thresholds = Vec::new();
    for i in 0..n {
        let idx = 1 + i * 2;
        if idx + 1 >= data.len() {
            break;
        }
        thresholds.push(ByteThreshold::new(data[idx], (data[idx + 1] as u16).max(1)));
    }
    if thresholds.is_empty() {
        return;
    }
    if let Ok(filter) = ByteFrequencyFilter::new(thresholds) {
        let off = 1 + n * 2;
        let input = if off < data.len() { &data[off..] } else { &[] };
        for w in filter.matching_windows(input) {
            assert!(w.offset as usize + w.length <= input.len());
        }
    }
});
