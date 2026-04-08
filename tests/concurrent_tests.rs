#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]
use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};
use std::sync::{Arc, Barrier};
use std::thread;

#[test]
fn test_concurrent_filtering() {
    let filter = Arc::new(
        ByteFrequencyFilter::new([ByteThreshold::new(b'a', 5)])
            .unwrap()
            .with_window_size(10)
            .unwrap(),
    );
    let barrier = Arc::new(Barrier::new(10));

    let mut handles = vec![];
    for _ in 0..10 {
        let f = Arc::clone(&filter);
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait();
            let data = b"aaaaabbbbbaaaaabbbbb";
            let matches = f.matching_windows(data);
            assert_eq!(matches.len(), 11, "Expected 11 matches");
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}
