#![no_main]
use libfuzzer_sys::fuzz_target;
use ebpfsieve::ByteFrequencyFilter;

fuzz_target!(|data: &[u8]| {
    // Must not panic on any input for any reasonable threshold config
    if data.len() < 2 { return; }
    let byte = data[0];
    let count = (data[1] as u16).max(1);
    let input = &data[2..];

    if let Ok(filter) = ByteFrequencyFilter::new(
        vec![ebpfsieve::ByteThreshold::new(byte, count)]
    ) {
        let _ = filter.matching_windows(input);
    }
});
