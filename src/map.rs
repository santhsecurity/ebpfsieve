//! Match window and byte threshold mappings.

/// Minimum required count for a single byte value inside a window.
///
/// # Example
///
/// ```rust
/// use ebpfsieve::ByteThreshold;
///
/// let threshold = ByteThreshold::new(b'a', 3);
/// assert_eq!(threshold.byte, b'a');
/// assert_eq!(threshold.min_count, 3);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ByteThreshold {
    /// The byte value that must appear.
    pub byte: u8,
    /// The minimum number of occurrences required in a matching window.
    pub min_count: u16,
}

impl ByteThreshold {
    /// Creates a threshold for one byte value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ebpfsieve::ByteThreshold;
    ///
    /// let t = ByteThreshold::new(b'x', 5);
    /// assert_eq!(t.byte, b'x');
    /// assert_eq!(t.min_count, 5);
    /// ```
    #[must_use]
    pub const fn new(byte: u8, min_count: u16) -> Self {
        Self { byte, min_count }
    }
}

/// Candidate byte range reported by the filter.
///
/// # Example
///
/// ```rust
/// use ebpfsieve::{ByteFrequencyFilter, ByteThreshold, MatchWindow};
///
/// let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 2)])
///     .unwrap()
///     .with_window_size(3)
///     .unwrap();
///
/// let matches = filter.matching_windows(b"aab");
/// assert_eq!(matches, vec![MatchWindow { offset: 0, length: 3 }]);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MatchWindow {
    /// Starting byte offset in the scanned stream.
    pub offset: u64,
    /// Number of bytes covered by the candidate window.
    pub length: usize,
}
/// Stack-allocated bitset for up to 256 thresholds, falling back to a `Vec` if larger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ThresholdBitset {
    Inline([u64; 4]),
    Heap(Vec<u64>),
}

impl ThresholdBitset {
    pub(crate) fn new(size: usize) -> Self {
        if size <= 256 {
            Self::Inline([0u64; 4])
        } else {
            Self::Heap(vec![0u64; (size + 63) / 64])
        }
    }

    #[inline]
    pub(crate) fn get(&self, index: usize) -> bool {
        let word = index / 64;
        let bit = index % 64;
        match self {
            Self::Inline(arr) => (arr[word] & (1u64 << bit)) != 0,
            Self::Heap(vec) => (vec[word] & (1u64 << bit)) != 0,
        }
    }

    #[inline]
    pub(crate) fn set(&mut self, index: usize) {
        let word = index / 64;
        let bit = index % 64;
        match self {
            Self::Inline(arr) => arr[word] |= 1u64 << bit,
            Self::Heap(vec) => vec[word] |= 1u64 << bit,
        }
    }

    #[inline]
    pub(crate) fn clear(&mut self, index: usize) {
        let word = index / 64;
        let bit = index % 64;
        match self {
            Self::Inline(arr) => arr[word] &= !(1u64 << bit),
            Self::Heap(vec) => vec[word] &= !(1u64 << bit),
        }
    }
}
