use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use tempfile::NamedTempFile;

#[test]
fn test_multiple_filters_same_file() {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(
        b"hello world, this is a very long string used for testing ebpfsieve functionality.",
    )
    .unwrap();

    let filter1 = ByteFrequencyFilter::new([ByteThreshold::new(b'e', 2)])
        .unwrap()
        .with_window_size(20)
        .unwrap();
    let filter2 = ByteFrequencyFilter::new([ByteThreshold::new(b'o', 2)])
        .unwrap()
        .with_window_size(20)
        .unwrap();

    let mut f1 = File::open(file.path()).unwrap();
    let matches1 = filter1.scan_file(&mut f1, None).unwrap();

    let mut f2 = File::open(file.path()).unwrap();
    let matches2 = filter2.scan_file(&mut f2, None).unwrap();

    assert!(matches1.len() > 0, "Should find 'e' matches");
    assert!(matches2.len() > 0, "Should find 'o' matches");
    assert_ne!(
        matches1.len(),
        matches2.len(),
        "Different thresholds should likely yield different match counts"
    );
}

#[test]
fn test_chunk_size_alignment_issues() {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(b"1234567890abcdefghijklmnopqrstuvwxyz")
        .unwrap();

    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
        .unwrap()
        .with_window_size(5)
        .unwrap()
        .with_chunk_size(3)
        .unwrap();

    let mut f = File::open(file.path()).unwrap();
    let matches = filter.scan_file(&mut f, None).unwrap();

    assert_eq!(
        matches.len(),
        5,
        "Should find exactly 5 matches for 'a' with window 5"
    );
}

#[test]
fn test_seek_and_scan() {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(b"1111111111xxxx2222222222").unwrap();
    file.seek(SeekFrom::Start(10)).unwrap();

    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 4)])
        .unwrap()
        .with_window_size(4)
        .unwrap();

    let mut f = File::open(file.path()).unwrap();
    f.seek(SeekFrom::Start(10)).unwrap();

    let matches = filter.scan_file(&mut f, None).unwrap();
    assert_eq!(
        matches.len(),
        1,
        "Should find the match right at the start of scan"
    );
    assert_eq!(matches[0].offset, 0, "Matches are relative to scan start");
}

#[test]
fn test_interrupted_reads() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 3)])
        .unwrap()
        .with_window_size(5)
        .unwrap();
    let data = b"aaaaa";

    struct SlowReader<'a> {
        data: &'a [u8],
        pos: usize,
    }

    impl std::io::Read for SlowReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.data.len() {
                return Ok(0);
            }
            buf[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }

    let mut attachment = filter.attach(SlowReader { data, pos: 0 });
    let mut matches = Vec::new();

    while let Ok(Some(chunk)) = attachment.read_next() {
        matches.extend(chunk.candidate_ranges);
    }

    assert!(
        matches.len() > 0,
        "Should correctly assemble matches across 1-byte reads"
    );
}

#[test]
fn test_extremely_large_file_scan_with_limit() {
    let mut file = NamedTempFile::new().unwrap();
    let chunk = vec![b'a'; 1024 * 1024];
    for _ in 0..50 {
        file.write_all(&chunk).unwrap();
    }

    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 10)])
        .unwrap()
        .with_window_size(100)
        .unwrap();

    let mut f = File::open(file.path()).unwrap();
    let matches = filter.scan_file(&mut f, Some(2 * 1024 * 1024)).unwrap();

    assert!(
        matches.len() > 1_000_000,
        "Should find many matches in the 2MB segment"
    );
}
