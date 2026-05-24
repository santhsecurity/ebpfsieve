use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};

macro_rules! test_accept {
    ($name:ident, $thresh:expr, $window:expr, $input:expr, $expected_offsets:expr) => {
        #[test]
        fn $name() {
            let filter = ByteFrequencyFilter::new($thresh)
                .unwrap()
                .with_window_size($window)
                .unwrap();
            let matches = filter.matching_windows($input);
            let offsets: Vec<u64> = matches.into_iter().map(|m| m.offset).collect();
            let expected: Vec<u64> = $expected_offsets.to_vec();
            assert_eq!(offsets, expected, "Mismatch in {}", stringify!($name));
        }
    };
}

// 50 Acceptance tests
test_accept!(accept_01, [ByteThreshold::new(b'A', 1)], 1, b"A", [0]);
test_accept!(accept_02, [ByteThreshold::new(b'A', 1)], 2, b"xA", [0]);
test_accept!(accept_03, [ByteThreshold::new(b'A', 1)], 2, b"Ax", [0]);
test_accept!(accept_04, [ByteThreshold::new(b'A', 1)], 1, b"xAx", [1]);
test_accept!(accept_05, [ByteThreshold::new(b'A', 1)], 3, b"xAx", [0]);
test_accept!(accept_06, [ByteThreshold::new(b'A', 2)], 2, b"AA", [0]);
test_accept!(accept_07, [ByteThreshold::new(b'A', 2)], 3, b"xAA", [0]);
test_accept!(accept_08, [ByteThreshold::new(b'A', 2)], 3, b"AxA", [0]);
test_accept!(accept_09, [ByteThreshold::new(b'A', 2)], 3, b"AAx", [0]);
test_accept!(
    accept_10,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 1)],
    2,
    b"AB",
    [0]
);

test_accept!(
    accept_11,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 1)],
    2,
    b"BA",
    [0]
);
test_accept!(
    accept_12,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 1)],
    3,
    b"xAB",
    [0]
);
test_accept!(
    accept_13,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 1)],
    3,
    b"AxB",
    [0]
);
test_accept!(
    accept_14,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 1)],
    3,
    b"ABx",
    [0]
);
test_accept!(
    accept_15,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 1)],
    3,
    b"BxA",
    [0]
);
test_accept!(
    accept_16,
    [ByteThreshold::new(b'A', 2), ByteThreshold::new(b'B', 2)],
    4,
    b"AABB",
    [0]
);
test_accept!(
    accept_17,
    [ByteThreshold::new(b'A', 2), ByteThreshold::new(b'B', 2)],
    4,
    b"BBAA",
    [0]
);
test_accept!(
    accept_18,
    [ByteThreshold::new(b'A', 2), ByteThreshold::new(b'B', 2)],
    4,
    b"ABAB",
    [0]
);
test_accept!(
    accept_19,
    [ByteThreshold::new(b'A', 2), ByteThreshold::new(b'B', 2)],
    5,
    b"AABBx",
    [0]
);
test_accept!(
    accept_20,
    [ByteThreshold::new(b'A', 2), ByteThreshold::new(b'B', 2)],
    5,
    b"xAABB",
    [0]
);

test_accept!(accept_21, [ByteThreshold::new(b'\0', 1)], 1, b"\0", [0]);
test_accept!(accept_22, [ByteThreshold::new(b'\0', 2)], 2, b"\0\0", [0]);
test_accept!(accept_23, [ByteThreshold::new(0xFF, 1)], 1, &[0xFF], [0]);
test_accept!(
    accept_24,
    [ByteThreshold::new(0xFF, 2)],
    2,
    &[0xFF, 0xFF],
    [0]
);
test_accept!(accept_25, [ByteThreshold::new(b'Z', 5)], 5, b"ZZZZZ", [0]);
test_accept!(accept_26, [ByteThreshold::new(b'Z', 5)], 6, b"xZZZZZ", [0]);
test_accept!(accept_27, [ByteThreshold::new(b'Z', 5)], 6, b"ZXZZZZ", [0]);
test_accept!(accept_28, [ByteThreshold::new(b'Z', 5)], 6, b"ZZZZZx", [0]);
test_accept!(
    accept_29,
    [
        ByteThreshold::new(b'A', 1),
        ByteThreshold::new(b'B', 1),
        ByteThreshold::new(b'C', 1)
    ],
    3,
    b"ABC",
    [0]
);
test_accept!(
    accept_30,
    [
        ByteThreshold::new(b'A', 1),
        ByteThreshold::new(b'B', 1),
        ByteThreshold::new(b'C', 1)
    ],
    3,
    b"CBA",
    [0]
);

test_accept!(
    accept_31,
    [
        ByteThreshold::new(b'A', 1),
        ByteThreshold::new(b'B', 1),
        ByteThreshold::new(b'C', 1)
    ],
    4,
    b"xABC",
    [0]
);
test_accept!(
    accept_32,
    [
        ByteThreshold::new(b'A', 1),
        ByteThreshold::new(b'B', 1),
        ByteThreshold::new(b'C', 1)
    ],
    4,
    b"AxBC",
    [0]
);
test_accept!(
    accept_33,
    [
        ByteThreshold::new(b'A', 1),
        ByteThreshold::new(b'B', 1),
        ByteThreshold::new(b'C', 1)
    ],
    4,
    b"ABxC",
    [0]
);
test_accept!(
    accept_34,
    [
        ByteThreshold::new(b'A', 1),
        ByteThreshold::new(b'B', 1),
        ByteThreshold::new(b'C', 1)
    ],
    4,
    b"ABCx",
    [0]
);
test_accept!(accept_35, [ByteThreshold::new(b'A', 3)], 5, b"AAxAx", [0]);
test_accept!(accept_36, [ByteThreshold::new(b'A', 3)], 5, b"xAxAA", [0]);
test_accept!(
    accept_37,
    [ByteThreshold::new(b'X', 10)],
    10,
    b"XXXXXXXXXX",
    [0]
);
test_accept!(
    accept_38,
    [ByteThreshold::new(b'X', 10)],
    15,
    b"abcXXXXXXXXXXdef",
    [0, 1]
);
test_accept!(
    accept_39,
    [
        ByteThreshold::new(b'1', 1),
        ByteThreshold::new(b'2', 1),
        ByteThreshold::new(b'3', 1),
        ByteThreshold::new(b'4', 1)
    ],
    4,
    b"1234",
    [0]
);
test_accept!(
    accept_40,
    [
        ByteThreshold::new(b'1', 1),
        ByteThreshold::new(b'2', 1),
        ByteThreshold::new(b'3', 1),
        ByteThreshold::new(b'4', 1)
    ],
    4,
    b"4321",
    [0]
);

test_accept!(
    accept_41,
    [
        ByteThreshold::new(b'1', 1),
        ByteThreshold::new(b'2', 1),
        ByteThreshold::new(b'3', 1),
        ByteThreshold::new(b'4', 1)
    ],
    5,
    b"x1234",
    [0]
);
test_accept!(accept_42, [ByteThreshold::new(b'M', 1)], 10, b"M", [0]); // window > payload
test_accept!(accept_43, [ByteThreshold::new(b'M', 2)], 10, b"MM", [0]);
test_accept!(
    accept_44,
    [ByteThreshold::new(b'A', 1)],
    1,
    b"AAAAAAAAAA",
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
); // multiple sequential windows
test_accept!(
    accept_45,
    [ByteThreshold::new(b'A', 2)],
    2,
    b"AAAAAAAAAA",
    [0, 1, 2, 3, 4, 5, 6, 7, 8]
); // multiple sequential windows
test_accept!(
    accept_46,
    [ByteThreshold::new(b'A', 3)],
    4,
    b"xAAAxAAAx",
    [0, 1, 2, 3, 4, 5]
); // non-contiguous windows
test_accept!(
    accept_47,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 1)],
    2,
    b"ABABABABAB",
    [0, 1, 2, 3, 4, 5, 6, 7, 8]
);
test_accept!(
    accept_48,
    [ByteThreshold::new(b'A', 2), ByteThreshold::new(b'B', 1)],
    3,
    b"AABBAA",
    [0, 3]
);
test_accept!(
    accept_49,
    [ByteThreshold::new(b'A', 1)],
    10,
    b"xAxAxAxAxA",
    [0]
);
test_accept!(
    accept_50,
    [ByteThreshold::new(b'A', 5)],
    10,
    b"xAxAxAxAxA",
    [0]
);

macro_rules! test_reject {
    ($name:ident, $thresh:expr, $window:expr, $input:expr) => {
        #[test]
        fn $name() {
            let filter = ByteFrequencyFilter::new($thresh)
                .unwrap()
                .with_window_size($window)
                .unwrap();
            let matches = filter.matching_windows($input);
            assert!(
                matches.is_empty(),
                "Expected empty matches, found {:?}",
                matches
            );
        }
    };
}

// 50 Rejection tests
test_reject!(reject_01, [ByteThreshold::new(b'A', 1)], 1, b"B");
test_reject!(reject_02, [ByteThreshold::new(b'A', 2)], 2, b"A");
test_reject!(reject_03, [ByteThreshold::new(b'A', 2)], 2, b"xA");
test_reject!(reject_04, [ByteThreshold::new(b'A', 2)], 2, b"Ax");
test_reject!(reject_05, [ByteThreshold::new(b'A', 2)], 1, b"AA"); // window too small
test_reject!(
    reject_06,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 1)],
    2,
    b"AC"
);
test_reject!(
    reject_07,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 1)],
    2,
    b"CB"
);
test_reject!(
    reject_08,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 1)],
    2,
    b"CC"
);
test_reject!(
    reject_09,
    [ByteThreshold::new(b'A', 2), ByteThreshold::new(b'B', 1)],
    3,
    b"ABB"
);
test_reject!(
    reject_10,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 2)],
    3,
    b"AAB"
);

test_reject!(reject_11, [ByteThreshold::new(b'Z', 5)], 5, b"ZZZZ");
test_reject!(reject_12, [ByteThreshold::new(b'Z', 5)], 5, b"xZZZZ");
test_reject!(reject_13, [ByteThreshold::new(b'Z', 5)], 5, b"ZZZZx");
test_reject!(reject_14, [ByteThreshold::new(b'Z', 5)], 5, b"ZZxZZ");
test_reject!(reject_15, [ByteThreshold::new(b'Z', 5)], 4, b"ZZZZZ"); // window too small
test_reject!(reject_16, [ByteThreshold::new(b'\0', 1)], 1, b"A");
test_reject!(reject_17, [ByteThreshold::new(b'\0', 2)], 2, b"\0A");
test_reject!(reject_18, [ByteThreshold::new(0xFF, 1)], 1, &[0xFE]);
test_reject!(reject_19, [ByteThreshold::new(0xFF, 2)], 2, &[0xFF, 0xFE]);
test_reject!(reject_20, [ByteThreshold::new(b'A', 10)], 10, b"AAAAAAAAA"); // 9 A's

test_reject!(reject_21, [ByteThreshold::new(b'A', 10)], 9, b"AAAAAAAAAA"); // 10 A's but window is 9
test_reject!(
    reject_22,
    [
        ByteThreshold::new(b'1', 1),
        ByteThreshold::new(b'2', 1),
        ByteThreshold::new(b'3', 1),
        ByteThreshold::new(b'4', 1)
    ],
    4,
    b"1235"
);
test_reject!(
    reject_23,
    [
        ByteThreshold::new(b'1', 1),
        ByteThreshold::new(b'2', 1),
        ByteThreshold::new(b'3', 1),
        ByteThreshold::new(b'4', 1)
    ],
    4,
    b"4325"
);
test_reject!(
    reject_24,
    [
        ByteThreshold::new(b'1', 1),
        ByteThreshold::new(b'2', 1),
        ByteThreshold::new(b'3', 1),
        ByteThreshold::new(b'4', 1)
    ],
    3,
    b"1234"
); // window 3
test_reject!(reject_25, [ByteThreshold::new(b'A', 2)], 3, b"AxxA"); // distance > window
test_reject!(reject_26, [ByteThreshold::new(b'A', 3)], 5, b"AAxxxA"); // spread out
test_reject!(
    reject_27,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 1)],
    2,
    b"AxxB"
); // spread out
test_reject!(
    reject_28,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 1)],
    3,
    b"AxxxB"
);
test_reject!(
    reject_29,
    [ByteThreshold::new(b'A', 2), ByteThreshold::new(b'B', 2)],
    4,
    b"AAB"
);
test_reject!(
    reject_30,
    [ByteThreshold::new(b'A', 2), ByteThreshold::new(b'B', 2)],
    4,
    b"ABB"
);

test_reject!(
    reject_31,
    [
        ByteThreshold::new(b'A', 1),
        ByteThreshold::new(b'B', 1),
        ByteThreshold::new(b'C', 1)
    ],
    3,
    b"ABD"
);
test_reject!(
    reject_32,
    [
        ByteThreshold::new(b'A', 1),
        ByteThreshold::new(b'B', 1),
        ByteThreshold::new(b'C', 1)
    ],
    3,
    b"DBC"
);
test_reject!(
    reject_33,
    [
        ByteThreshold::new(b'A', 1),
        ByteThreshold::new(b'B', 1),
        ByteThreshold::new(b'C', 1)
    ],
    3,
    b"ADC"
);
test_reject!(
    reject_34,
    [
        ByteThreshold::new(b'A', 1),
        ByteThreshold::new(b'B', 1),
        ByteThreshold::new(b'C', 1)
    ],
    2,
    b"ABC"
); // window too small
test_reject!(reject_35, [ByteThreshold::new(b'X', 5)], 10, b"XXXX"); // not enough X
test_reject!(reject_36, [ByteThreshold::new(b'X', 5)], 10, b"xXxxXxXxxX"); // 4 X
test_reject!(reject_37, [ByteThreshold::new(b'A', 1)], 10, b""); // empty payload handled in empty tests
test_reject!(
    reject_38,
    [ByteThreshold::new(b'A', 5), ByteThreshold::new(b'B', 5)],
    10,
    b"AAAAABBBB"
); // 5A, 4B
test_reject!(
    reject_39,
    [ByteThreshold::new(b'A', 5), ByteThreshold::new(b'B', 5)],
    10,
    b"AAAABBBBB"
); // 4A, 5B
test_reject!(reject_40, [ByteThreshold::new(b'M', 2)], 10, b"M"); // payload < min

test_reject!(reject_41, [ByteThreshold::new(b'M', 2)], 10, b"MxxxxxxxxxM"); // 2 M's but only in window if payload > 2... wait, if payload is "MxM" len is 3. window 10. so it matches. Let's fix this.
test_reject!(reject_42, [ByteThreshold::new(b'A', 2)], 2, b"A A");
test_reject!(reject_43, [ByteThreshold::new(b'A', 2)], 3, b"A  A"); // space 2, distance 3 so fits in 4. window 3. rejects!
test_reject!(reject_44, [ByteThreshold::new(b'A', 2)], 4, b"A   A");
test_reject!(reject_45, [ByteThreshold::new(b'A', 2)], 5, b"A    A");
test_reject!(
    reject_46,
    [ByteThreshold::new(b'A', 2), ByteThreshold::new(b'B', 2)],
    4,
    b"ABA "
);
test_reject!(
    reject_47,
    [ByteThreshold::new(b'A', 2), ByteThreshold::new(b'B', 2)],
    4,
    b" BAB"
);
test_reject!(
    reject_48,
    [ByteThreshold::new(b'A', 2), ByteThreshold::new(b'B', 2)],
    3,
    b"ABAB"
); // window too small
test_reject!(
    reject_49,
    [ByteThreshold::new(0xFF, 3)],
    3,
    &[0xFF, 0xFE, 0xFF]
);
test_reject!(
    reject_50,
    [ByteThreshold::new(0x00, 3)],
    3,
    &[0x00, 0x01, 0x00]
);

fn all_bytes_thresholds() -> Vec<ByteThreshold> {
    (0..=255).map(|b: u8| ByteThreshold::new(b, 1)).collect()
}

macro_rules! test_all_bytes {
    ($name:ident, $window:expr, $input:expr, $expected_offsets:expr) => {
        #[test]
        fn $name() {
            let filter = ByteFrequencyFilter::new(all_bytes_thresholds())
                .unwrap()
                .with_window_size($window)
                .unwrap();
            let matches = filter.matching_windows($input);
            let offsets: Vec<u64> = matches.into_iter().map(|m| m.offset).collect();
            let expected: Vec<u64> = $expected_offsets.to_vec();
            assert_eq!(offsets, expected, "Mismatch in {}", stringify!($name));
        }
    };
}

// 20 All-byte threshold tests
test_all_bytes!(all_bytes_01, 256, &(0..=255).collect::<Vec<u8>>(), [0]);
test_all_bytes!(
    all_bytes_02,
    256,
    &(0..=255).rev().collect::<Vec<u8>>(),
    [0]
);
test_all_bytes!(all_bytes_03, 255, &(0..=255).collect::<Vec<u8>>(), []); // window too small
test_all_bytes!(all_bytes_04, 257, &(0..=255).collect::<Vec<u8>>(), [0]); // window larger than payload but payload has all
test_all_bytes!(all_bytes_05, 256, &[0; 256], []); // missing other bytes

fn shift_bytes(shift: u8) -> Vec<u8> {
    (0..=255).map(|b: u8| b.wrapping_add(shift)).collect()
}

test_all_bytes!(all_bytes_06, 256, &shift_bytes(10), [0]);
test_all_bytes!(all_bytes_07, 256, &shift_bytes(128), [0]);

fn double_bytes() -> Vec<u8> {
    let mut v = Vec::new();
    for b in 0..=255 {
        v.push(b);
        v.push(b);
    }
    v
}

test_all_bytes!(all_bytes_08, 512, &double_bytes(), [0]);
test_all_bytes!(all_bytes_09, 256, &double_bytes(), []); // Needs 256 distinct bytes in window 256, but input has duplicates sequentially

fn all_bytes_with_padding() -> Vec<u8> {
    let mut v = vec![0, 0, 0];
    v.extend(0..=255);
    v.push(0);
    v.push(0);
    v
}

test_all_bytes!(all_bytes_10, 256, &all_bytes_with_padding(), [3, 4]);
test_all_bytes!(all_bytes_11, 257, &all_bytes_with_padding(), [2, 3, 4]);

fn almost_all_bytes() -> Vec<u8> {
    let mut v: Vec<u8> = (0..=255).collect();
    v[255] = 0; // duplicate 0, missing 255
    v
}

test_all_bytes!(all_bytes_12, 256, &almost_all_bytes(), []);
test_all_bytes!(all_bytes_13, 1024, &almost_all_bytes(), []);

fn alternating_all_bytes() -> Vec<u8> {
    let mut v = Vec::new();
    for i in 0..128 {
        v.push(i);
        v.push(255 - i);
    }
    v
}

test_all_bytes!(all_bytes_14, 256, &alternating_all_bytes(), [0]);
test_all_bytes!(all_bytes_15, 256, &[], []);

fn sequential_all_bytes_repeated() -> Vec<u8> {
    let mut v: Vec<u8> = (0..=255).collect();
    v.extend(0..=255);
    v
}

test_all_bytes!(
    all_bytes_16,
    256,
    &sequential_all_bytes_repeated(),
    [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70,
        71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93,
        94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112,
        113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130,
        131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148,
        149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166,
        167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184,
        185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202,
        203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220,
        221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238,
        239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256
    ]
);

test_all_bytes!(all_bytes_17, 512, &sequential_all_bytes_repeated(), [0]);

fn randomish_all_bytes() -> Vec<u8> {
    let mut v: Vec<u8> = (0..=255).collect();
    v.swap(0, 100);
    v.swap(50, 200);
    v.swap(10, 250);
    v
}

test_all_bytes!(all_bytes_18, 256, &randomish_all_bytes(), [0]);
test_all_bytes!(all_bytes_19, 255, &randomish_all_bytes(), []);
test_all_bytes!(all_bytes_20, 260, &randomish_all_bytes(), [0]);

macro_rules! test_high_threshold {
    ($name:ident, $thresh:expr, $window:expr, $input:expr, $expected_offsets:expr) => {
        #[test]
        fn $name() {
            let filter = ByteFrequencyFilter::new($thresh)
                .unwrap()
                .with_window_size($window)
                .unwrap();
            let matches = filter.matching_windows($input);
            let offsets: Vec<u64> = matches.into_iter().map(|m| m.offset).collect();
            let expected: Vec<u64> = $expected_offsets.to_vec();
            assert_eq!(offsets, expected, "Mismatch in {}", stringify!($name));
        }
    };
}

fn repeated_bytes(b: u8, count: usize) -> Vec<u8> {
    vec![b; count]
}

// 20 High-threshold tests (count = 255)
test_high_threshold!(
    high_thresh_01,
    [ByteThreshold::new(b'H', 255)],
    255,
    &repeated_bytes(b'H', 255),
    [0]
);
test_high_threshold!(
    high_thresh_02,
    [ByteThreshold::new(b'H', 255)],
    255,
    &repeated_bytes(b'H', 254),
    []
);
test_high_threshold!(
    high_thresh_03,
    [ByteThreshold::new(b'H', 255)],
    255,
    &repeated_bytes(b'H', 256),
    [0, 1]
);
test_high_threshold!(
    high_thresh_04,
    [ByteThreshold::new(b'H', 255)],
    256,
    &repeated_bytes(b'H', 255),
    [0]
);
test_high_threshold!(
    high_thresh_05,
    [ByteThreshold::new(b'H', 255)],
    256,
    &repeated_bytes(b'H', 256),
    [0]
); // window 256, input 256, it fits all 256 H's which is >= 255

fn repeated_with_noise(b: u8, count: usize, pad: usize) -> Vec<u8> {
    let mut v = vec![b'X'; pad];
    v.extend(vec![b; count]);
    v.extend(vec![b'Y'; pad]);
    v
}

test_high_threshold!(
    high_thresh_06,
    [ByteThreshold::new(b'H', 255)],
    255,
    &repeated_with_noise(b'H', 255, 10),
    [10]
);
test_high_threshold!(
    high_thresh_07,
    [ByteThreshold::new(b'H', 255)],
    256,
    &repeated_with_noise(b'H', 255, 10),
    [9, 10]
); // window 256 -> can include 1 pad byte
test_high_threshold!(
    high_thresh_08,
    [ByteThreshold::new(b'H', 255)],
    255,
    &repeated_with_noise(b'H', 254, 10),
    []
);

test_high_threshold!(
    high_thresh_09,
    [ByteThreshold::new(b'A', 255), ByteThreshold::new(b'B', 255)],
    510,
    &[repeated_bytes(b'A', 255), repeated_bytes(b'B', 255)].concat(),
    [0]
);
test_high_threshold!(
    high_thresh_10,
    [ByteThreshold::new(b'A', 255), ByteThreshold::new(b'B', 255)],
    510,
    &[repeated_bytes(b'A', 254), repeated_bytes(b'B', 256)].concat(),
    []
);
test_high_threshold!(
    high_thresh_11,
    [ByteThreshold::new(b'A', 255), ByteThreshold::new(b'B', 255)],
    510,
    &[repeated_bytes(b'B', 255), repeated_bytes(b'A', 255)].concat(),
    [0]
);
test_high_threshold!(
    high_thresh_12,
    [ByteThreshold::new(b'A', 255), ByteThreshold::new(b'B', 255)],
    511,
    &[repeated_bytes(b'A', 255), repeated_bytes(b'B', 255)].concat(),
    [0]
); // window > payload

fn interspersed(a: u8, count: usize) -> Vec<u8> {
    let mut v = Vec::new();
    for _ in 0..count {
        v.push(a);
        v.push(b'N');
    }
    v
}

test_high_threshold!(
    high_thresh_13,
    [ByteThreshold::new(b'K', 255)],
    510,
    &interspersed(b'K', 255),
    [0]
); // 255 K's spread over 510 bytes
test_high_threshold!(
    high_thresh_14,
    [ByteThreshold::new(b'K', 255)],
    509,
    &interspersed(b'K', 255),
    [0]
); // last byte is K
test_high_threshold!(
    high_thresh_15,
    [ByteThreshold::new(b'K', 255)],
    508,
    &interspersed(b'K', 255),
    []
); // misses the last K

test_high_threshold!(
    high_thresh_16,
    [ByteThreshold::new(b'H', 255)],
    255,
    b"",
    []
);
test_high_threshold!(
    high_thresh_17,
    [ByteThreshold::new(b'H', 255)],
    255,
    b"H",
    []
);

fn all_255s() -> Vec<u8> {
    vec![255; 255]
}

test_high_threshold!(
    high_thresh_18,
    [ByteThreshold::new(255, 255)],
    255,
    &all_255s(),
    [0]
);
test_high_threshold!(
    high_thresh_19,
    [ByteThreshold::new(255, 255)],
    255,
    &vec![255; 254],
    []
);
test_high_threshold!(
    high_thresh_20,
    [ByteThreshold::new(0, 255)],
    255,
    &vec![0; 255],
    [0]
);

use std::sync::Arc;
use std::thread;

macro_rules! test_concurrent {
    ($name:ident, $thresh:expr, $window:expr, $input:expr, $expected_offsets:expr) => {
        #[test]
        fn $name() {
            let filter = Arc::new(
                ByteFrequencyFilter::new($thresh)
                    .unwrap()
                    .with_window_size($window)
                    .unwrap(),
            );

            let mut handles = vec![];

            for _ in 0..8 {
                // 8 threads
                let filter_clone = Arc::clone(&filter);
                let input_clone = $input.to_vec();
                let expected: Vec<u64> = $expected_offsets.to_vec();

                handles.push(thread::spawn(move || {
                    let matches = filter_clone.matching_windows(&input_clone);
                    let offsets: Vec<u64> = matches.into_iter().map(|m| m.offset).collect();
                    assert_eq!(offsets, expected, "Mismatch in concurrent thread");
                }));
            }

            for handle in handles {
                handle.join().unwrap();
            }
        }
    };
}

// 20 Concurrent tests
test_concurrent!(concurrent_01, [ByteThreshold::new(b'A', 1)], 1, b"A", [0]);
test_concurrent!(concurrent_02, [ByteThreshold::new(b'A', 1)], 2, b"xA", [0]);
test_concurrent!(concurrent_03, [ByteThreshold::new(b'A', 1)], 2, b"Ax", [0]);
test_concurrent!(concurrent_04, [ByteThreshold::new(b'A', 1)], 1, b"xAx", [1]);
test_concurrent!(concurrent_05, [ByteThreshold::new(b'A', 1)], 3, b"xAx", [0]);
test_concurrent!(concurrent_06, [ByteThreshold::new(b'A', 2)], 2, b"AA", [0]);
test_concurrent!(concurrent_07, [ByteThreshold::new(b'A', 2)], 3, b"xAA", [0]);
test_concurrent!(concurrent_08, [ByteThreshold::new(b'A', 2)], 3, b"AxA", [0]);
test_concurrent!(concurrent_09, [ByteThreshold::new(b'A', 2)], 3, b"AAx", [0]);
test_concurrent!(
    concurrent_10,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 1)],
    2,
    b"AB",
    [0]
);

test_concurrent!(
    concurrent_11,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 1)],
    2,
    b"BA",
    [0]
);
test_concurrent!(
    concurrent_12,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 1)],
    3,
    b"xAB",
    [0]
);
test_concurrent!(
    concurrent_13,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 1)],
    3,
    b"AxB",
    [0]
);
test_concurrent!(
    concurrent_14,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 1)],
    3,
    b"ABx",
    [0]
);
test_concurrent!(
    concurrent_15,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 1)],
    3,
    b"BxA",
    [0]
);
test_concurrent!(
    concurrent_16,
    [ByteThreshold::new(b'A', 2), ByteThreshold::new(b'B', 2)],
    4,
    b"AABB",
    [0]
);
test_concurrent!(
    concurrent_17,
    [ByteThreshold::new(b'A', 2), ByteThreshold::new(b'B', 2)],
    4,
    b"BBAA",
    [0]
);
test_concurrent!(
    concurrent_18,
    [ByteThreshold::new(b'A', 2), ByteThreshold::new(b'B', 2)],
    4,
    b"ABAB",
    [0]
);
test_concurrent!(
    concurrent_19,
    [ByteThreshold::new(b'A', 2), ByteThreshold::new(b'B', 2)],
    5,
    b"AABBx",
    [0]
);
test_concurrent!(
    concurrent_20,
    [ByteThreshold::new(b'A', 2), ByteThreshold::new(b'B', 2)],
    5,
    b"xAABB",
    [0]
);

macro_rules! test_empty {
    ($name:ident, $thresh:expr, $window:expr) => {
        #[test]
        fn $name() {
            let filter = ByteFrequencyFilter::new($thresh)
                .unwrap()
                .with_window_size($window)
                .unwrap();
            let matches = filter.matching_windows(b"");
            assert!(
                matches.is_empty(),
                "Expected empty matches, found {:?}",
                matches
            );
        }
    };
}

// 10 Empty input tests
test_empty!(empty_01, [ByteThreshold::new(b'A', 1)], 1);
test_empty!(empty_02, [ByteThreshold::new(b'A', 1)], 10);
test_empty!(empty_03, [ByteThreshold::new(b'A', 5)], 10);
test_empty!(empty_04, [ByteThreshold::new(b'\0', 1)], 1);
test_empty!(empty_05, [ByteThreshold::new(b'\0', 5)], 10);
test_empty!(empty_06, [ByteThreshold::new(0xFF, 1)], 1);
test_empty!(empty_07, [ByteThreshold::new(0xFF, 5)], 10);
test_empty!(
    empty_08,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 1)],
    2
);
test_empty!(empty_09, all_bytes_thresholds(), 256);
test_empty!(empty_10, [ByteThreshold::new(b'A', 255)], 255);

macro_rules! test_all_zeros {
    ($name:ident, $thresh:expr, $window:expr, $len:expr, $expected_offsets:expr) => {
        #[test]
        fn $name() {
            let filter = ByteFrequencyFilter::new($thresh)
                .unwrap()
                .with_window_size($window)
                .unwrap();
            let input = vec![0u8; $len];
            let matches = filter.matching_windows(&input);
            let offsets: Vec<u64> = matches.into_iter().map(|m| m.offset).collect();
            let expected: Vec<u64> = $expected_offsets.to_vec();
            assert_eq!(offsets, expected, "Mismatch in {}", stringify!($name));
        }
    };
}

// 10 All-zero input tests
test_all_zeros!(all_zero_01, [ByteThreshold::new(0, 1)], 1, 1, [0]);
test_all_zeros!(all_zero_02, [ByteThreshold::new(0, 1)], 2, 2, [0]);
test_all_zeros!(all_zero_03, [ByteThreshold::new(0, 5)], 5, 5, [0]);
test_all_zeros!(all_zero_04, [ByteThreshold::new(0, 5)], 6, 6, [0]);
test_all_zeros!(all_zero_05, [ByteThreshold::new(1, 1)], 1, 10, []);
test_all_zeros!(
    all_zero_06,
    [ByteThreshold::new(0, 10)],
    10,
    15,
    [0, 1, 2, 3, 4, 5]
);
test_all_zeros!(all_zero_07, [ByteThreshold::new(0, 255)], 255, 255, [0]);
test_all_zeros!(all_zero_08, [ByteThreshold::new(0, 255)], 255, 254, []);
test_all_zeros!(all_zero_09, all_bytes_thresholds(), 256, 1000, []); // all 0s, missing 1..=255
test_all_zeros!(
    all_zero_10,
    [ByteThreshold::new(0, 10), ByteThreshold::new(1, 1)],
    11,
    20,
    []
);

macro_rules! test_all_ff {
    ($name:ident, $thresh:expr, $window:expr, $len:expr, $expected_offsets:expr) => {
        #[test]
        fn $name() {
            let filter = ByteFrequencyFilter::new($thresh)
                .unwrap()
                .with_window_size($window)
                .unwrap();
            let input = vec![0xFFu8; $len];
            let matches = filter.matching_windows(&input);
            let offsets: Vec<u64> = matches.into_iter().map(|m| m.offset).collect();
            let expected: Vec<u64> = $expected_offsets.to_vec();
            assert_eq!(offsets, expected, "Mismatch in {}", stringify!($name));
        }
    };
}

// 10 All-0xFF input tests
test_all_ff!(all_ff_01, [ByteThreshold::new(0xFF, 1)], 1, 1, [0]);
test_all_ff!(all_ff_02, [ByteThreshold::new(0xFF, 1)], 2, 2, [0]);
test_all_ff!(all_ff_03, [ByteThreshold::new(0xFF, 5)], 5, 5, [0]);
test_all_ff!(all_ff_04, [ByteThreshold::new(0xFF, 5)], 6, 6, [0]);
test_all_ff!(all_ff_05, [ByteThreshold::new(0xFE, 1)], 1, 10, []);
test_all_ff!(
    all_ff_06,
    [ByteThreshold::new(0xFF, 10)],
    10,
    15,
    [0, 1, 2, 3, 4, 5]
);
test_all_ff!(all_ff_07, [ByteThreshold::new(0xFF, 255)], 255, 255, [0]);
test_all_ff!(all_ff_08, [ByteThreshold::new(0xFF, 255)], 255, 254, []);
test_all_ff!(all_ff_09, all_bytes_thresholds(), 256, 1000, []); // all FF, missing 0..=254
test_all_ff!(
    all_ff_10,
    [ByteThreshold::new(0xFF, 10), ByteThreshold::new(0xFE, 1)],
    11,
    20,
    []
);

macro_rules! test_window_boundary {
    ($name:ident, $thresh:expr, $window:expr, $input:expr, $expected_offsets:expr) => {
        #[test]
        fn $name() {
            let filter = ByteFrequencyFilter::new($thresh)
                .unwrap()
                .with_window_size($window)
                .unwrap();
            let matches = filter.matching_windows($input);
            let offsets: Vec<u64> = matches.into_iter().map(|m| m.offset).collect();
            let expected: Vec<u64> = $expected_offsets.to_vec();
            assert_eq!(offsets, expected, "Mismatch in {}", stringify!($name));
        }
    };
}

// 10 Window size boundary tests
test_window_boundary!(
    window_bounds_01,
    [ByteThreshold::new(b'A', 1)],
    1,
    b"A",
    [0]
);
test_window_boundary!(
    window_bounds_02,
    [ByteThreshold::new(b'A', 1)],
    usize::MAX,
    b"A",
    [0]
);
test_window_boundary!(
    window_bounds_03,
    [ByteThreshold::new(b'A', 2)],
    usize::MAX,
    b"A A",
    [0]
); // window wraps entire payload
test_window_boundary!(
    window_bounds_04,
    [ByteThreshold::new(b'A', 2)],
    1000,
    b"A                                  A",
    [0]
); // far apart, large window
test_window_boundary!(
    window_bounds_05,
    [ByteThreshold::new(b'A', 1)],
    2,
    b"A",
    [0]
); // window > payload length
test_window_boundary!(
    window_bounds_06,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 1)],
    1,
    b"AB",
    []
); // window 1 too small for both
test_window_boundary!(
    window_bounds_07,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 1)],
    2,
    b"AB",
    [0]
);
test_window_boundary!(
    window_bounds_08,
    [ByteThreshold::new(b'A', 1), ByteThreshold::new(b'B', 1)],
    100,
    b"AB",
    [0]
); // window > payload
test_window_boundary!(
    window_bounds_09,
    [ByteThreshold::new(b'A', 10)],
    10,
    b"AAAAAAAAAA",
    [0]
); // window == payload
test_window_boundary!(
    window_bounds_10,
    [ByteThreshold::new(b'A', 10)],
    9,
    b"AAAAAAAAAA",
    []
); // window < payload but too small for 10
