//! Zero-allocation sliding window iterator for byte frequency matching.

use crate::map::ThresholdBitset;
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
    counts: [usize; 256],
    pos: usize,
    initialized: bool,
    /// Windows yielded so far. The iterator stops once it reaches the filter's
    /// `max_matches`, so it and the collecting `matching_windows()` surface the
    /// same number of windows instead of the iterator running unbounded.
    emitted: usize,
    satisfied: usize,
    threshold_met: ThresholdBitset,
}

impl<'a> MatchWindowIter<'a> {
    pub(crate) fn new(filter: &'a ByteFrequencyFilter, bytes: &'a [u8]) -> Self {
        let window = filter.window_size().min(bytes.len());
        let total_thresholds = filter.thresholds().len();
        Self {
            filter,
            bytes,
            window,
            counts: [0usize; 256],
            pos: 0,
            initialized: false,
            emitted: 0,
            satisfied: 0,
            threshold_met: ThresholdBitset::new(total_thresholds),
        }
    }
}

impl Iterator for MatchWindowIter<'_> {
    type Item = MatchWindow;

    fn next(&mut self) -> Option<MatchWindow> {
        if self.bytes.len() < self.window {
            return None;
        }
        // Honor the filter's max_matches so the iterator and the collecting
        // matching_windows() agree on how many windows they surface.
        if self.emitted >= self.filter.max_matches() {
            return None;
        }

        let total_thresholds = self.filter.thresholds().len();

        if !self.initialized {
            for &byte in &self.bytes[..self.window] {
                self.counts[byte as usize] += 1;
            }
            for (i, t) in self.filter.thresholds().iter().enumerate() {
                if self.counts[t.byte as usize] >= usize::from(t.min_count) {
                    self.threshold_met.set(i);
                    self.satisfied += 1;
                }
            }
            self.initialized = true;
            self.pos = 1;
            if self.satisfied == total_thresholds {
                self.emitted += 1;
                return Some(MatchWindow {
                    offset: 0,
                    length: self.window,
                });
            }
        }

        let byte_to_thresholds = self.filter.byte_to_threshold_indices();
        while self.pos + self.window <= self.bytes.len() {
            let removed = self.bytes[self.pos - 1] as usize;
            let added = self.bytes[self.pos + self.window - 1] as usize;
            self.counts[removed] = self.counts[removed].saturating_sub(1);
            self.counts[added] += 1;
            let pos = self.pos;
            self.pos += 1;

            if removed != added {
                for &ti in &byte_to_thresholds[removed] {
                    let was_met = self.threshold_met.get(ti);
                    let now_met = self.counts[self.filter.thresholds()[ti].byte as usize]
                        >= usize::from(self.filter.thresholds()[ti].min_count);
                    if was_met && !now_met {
                        self.satisfied -= 1;
                        self.threshold_met.clear(ti);
                    }
                }
                for &ti in &byte_to_thresholds[added] {
                    let was_met = self.threshold_met.get(ti);
                    let now_met = self.counts[self.filter.thresholds()[ti].byte as usize]
                        >= usize::from(self.filter.thresholds()[ti].min_count);
                    if !was_met && now_met {
                        self.satisfied += 1;
                        self.threshold_met.set(ti);
                    }
                }
            }

            if self.satisfied == total_thresholds {
                self.emitted += 1;
                return Some(MatchWindow {
                    offset: pos as u64,
                    length: self.window,
                });
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use crate::{ByteFrequencyFilter, ByteThreshold};

    #[test]
    fn iterator_respects_max_matches() {
        // "aaaa" has three size-2 windows (offsets 0,1,2) that all satisfy the
        // threshold. With max_matches = 2 the iterator must stop at 2, agreeing
        // with the collecting matching_windows(); it previously ran unbounded.
        let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
            .unwrap()
            .with_window_size(2)
            .unwrap()
            .with_max_matches(2);

        let via_iter: Vec<_> = filter.matching_windows_iter(b"aaaa").collect();
        assert_eq!(via_iter.len(), 2, "iterator must cap at max_matches");
        assert_eq!(
            filter.matching_windows(b"aaaa").len(),
            2,
            "collecting method caps at max_matches too"
        );
    }

    #[test]
    fn iterator_and_matching_windows_are_identical() {
        let filter = ByteFrequencyFilter::new([
            ByteThreshold::new(b'a', 2),
            ByteThreshold::new(b'b', 1),
        ])
        .unwrap()
        .with_window_size(4)
        .unwrap();

        let data = b"xxaabxxbaaxxaabxxaabxx";
        let via_vec = filter.matching_windows(data);
        let via_iter: Vec<_> = filter.matching_windows_iter(data).collect();
        assert_eq!(via_vec, via_iter, "iterator and matching_windows must produce identical windows");
    }
}
