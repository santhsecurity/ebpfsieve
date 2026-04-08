use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let t = ByteThreshold::new(b'A', u16::MAX);
    let filter = ByteFrequencyFilter::new([t])?.with_window_size(65538)?;
    let input = vec![b'A'; 65538];
    let matches = filter.matching_windows(&input);
    println!("Test 1 (u16::MAX undercount) matches: {}", matches.len());

    let matches_iter: Vec<_> = filter.matching_windows_iter(&input).collect();
    println!("Test 2 (u16::MAX iter) matches: {}", matches_iter.len());
    Ok(())
}
