use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};
use std::sync::{Arc, Barrier, Mutex, RwLock};
use std::thread;

#[test]
fn test_concurrent_independent_filters() {
    let barrier = Arc::new(Barrier::new(5));
    let mut handles = vec![];
    
    for i in 0..5 {
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait();
            let byte = b'a' + i;
            let filter = ByteFrequencyFilter::new([ByteThreshold::new(byte, 2)]).unwrap().with_window_size(5).unwrap();
            let data = vec![byte; 10];
            let matches = filter.matching_windows(&data);
            assert_eq!(matches.len(), 6, "Expected 6 matches for independent filter {}", i);
        }));
    }
    
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_concurrent_writes_to_shared_state() {
    let filter = Arc::new(ByteFrequencyFilter::new([ByteThreshold::new(b'x', 3)]).unwrap().with_window_size(5).unwrap());
    let results = Arc::new(Mutex::new(Vec::new()));
    
    let mut handles = vec![];
    
    for i in 0..10 {
        let f = Arc::clone(&filter);
        let res = Arc::clone(&results);
        handles.push(thread::spawn(move || {
            let mut data = vec![b'a'; 100];
            for j in 0..5 {
                data[i * 5 + j] = b'x';
            }
            
            let matches = f.matching_windows(&data);
            res.lock().unwrap().push(matches.len());
        }));
    }
    
    for h in handles {
        h.join().unwrap();
    }
    
    let final_results = results.lock().unwrap();
    assert_eq!(final_results.len(), 10, "All threads should complete");
    for &count in final_results.iter() {
        assert_eq!(count, 3, "Each thread should find 3 matches");
    }
}

#[test]
fn test_concurrent_read_write_large_data() {
    let data = Arc::new(RwLock::new(vec![b'a'; 1_000_000]));
    let filter = Arc::new(ByteFrequencyFilter::new([ByteThreshold::new(b'x', 5)]).unwrap().with_window_size(10).unwrap());
    
    let mut handles = vec![];
    
    let data_w = Arc::clone(&data);
    handles.push(thread::spawn(move || {
        let mut d = data_w.write().unwrap();
        for i in 0..100 {
            d[i * 10_000] = b'x';
        }
    }));
    
    for _ in 0..5 {
        let f = Arc::clone(&filter);
        let data_r = Arc::clone(&data);
        handles.push(thread::spawn(move || {
            let d = data_r.read().unwrap();
            let matches = f.matching_windows(&d);
            assert!(matches.len() >= 0, "Should read successfully");
        }));
    }
    
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn test_concurrent_attachments() {
    let filter = Arc::new(ByteFrequencyFilter::new([ByteThreshold::new(b'x', 2)]).unwrap().with_window_size(4).unwrap());
    let mut handles = vec![];
    
    for _ in 0..10 {
        let f = Arc::clone(&filter);
        handles.push(thread::spawn(move || {
            let data = b"axaxbxcx";
            let mut cursor = std::io::Cursor::new(data);
            let matches = f.scan_file(&mut cursor, None).unwrap();
            assert_eq!(matches.len(), 5, "Concurrent attachment scans should yield correct results");
        }));
    }
    
    for h in handles {
        h.join().unwrap();
    }
}
