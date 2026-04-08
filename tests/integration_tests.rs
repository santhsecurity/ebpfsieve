#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]
use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};
use std::fs::File;
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_end_to_end_file_scan() {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(
        b"this is a test file with some data that we will scan. xxxx is what we want to find.",
    )
    .unwrap();

    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 4)])
        .unwrap()
        .with_window_size(10)
        .unwrap();
    let mut f = File::open(file.path()).unwrap();
    let matches = filter.scan_file(&mut f, None).unwrap();

    assert_eq!(matches.len(), 7, "Expected exactly 7 matches in the file");
}
