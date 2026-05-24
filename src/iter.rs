//! Zero-allocation sliding window iterator for byte frequency matching.

use crate::{ByteFrequencyFilter, MatchWindow};

/// Zero-allocation iterator over matching windows.
///
/// Slides a fixed-size window over the input bytes, maintaining
/// a running frequency histogram and yielding windows where all
/// byte thresholds are met.
///
/// # Example
///
/// ```rust
/// use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};
///
/// let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 2)])
///     .unwrap()
///     .with_window_size(3)
///     .unwrap();
///
/// let mut iter = filter.matching_windows_iter(b"abac");
/// assert_eq!(iter.next().unwrap().offset, 0); // "aba"
/// assert!(iter.next().is_none());
/// ```
pub struct MatchWindowIter<'a> {
    filter: &'a ByteFrequencyFilter,
    bytes: &'a [u8],
    window: usize,
    counts: [u16; 256],
    pos: usize,
    initialized: bool,
}

impl<'a> MatchWindowIter<'a> {
    pub(crate) fn new(filter: &'a ByteFrequencyFilter, bytes: &'a [u8]) -> Self {
        let window = filter.window_size().min(bytes.len());
        Self {
            filter,
            bytes,
            window,
            counts: [0u16; 256],
            pos: 0,
            initialized: false,
        }
    }
}

impl Iterator for MatchWindowIter<'_> {
    type Item = MatchWindow;

    fn next(&mut self) -> Option<MatchWindow> {
        if self.bytes.len() < self.window {
            return None;
        }

        if !self.initialized {
            for &byte in &self.bytes[..self.window] {
                self.counts[byte as usize] = self.counts[byte as usize].saturating_add(1);
            }
            self.initialized = true;
            self.pos = 1;
            if self.filter.window_matches(&self.counts) {
                return Some(MatchWindow {
                    offset: 0,
                    length: self.window,
                });
            }
        }

        while self.pos + self.window <= self.bytes.len() {
            let removed = self.bytes[self.pos - 1] as usize;
            let added = self.bytes[self.pos + self.window - 1] as usize;
            self.counts[removed] = self.counts[removed].saturating_sub(1);
            self.counts[added] = self.counts[added].saturating_add(1);
            let pos = self.pos;
            self.pos += 1;
            if self.filter.window_matches(&self.counts) {
                return Some(MatchWindow {
                    offset: pos as u64,
                    length: self.window,
                });
            }
        }

        None
    }
}
