use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let t = ByteThreshold::new(b'A', 1);
    let filter = ByteFrequencyFilter::new([t])?.with_window_size(2)?;
    let input = b"AAAA";

    let mut iter = filter.matching_windows_iter(input);
    println!("{:?}", iter.next()); // Should return offset 0
    println!("{:?}", iter.next()); // Panics!
    Ok(())
}
