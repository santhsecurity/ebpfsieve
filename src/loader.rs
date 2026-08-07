//! File reading and chunk loading.

use crate::error::{Error, Result};
use crate::kernel::KernelFilter;
use crate::map::MatchWindow;
use crate::program::ByteFrequencyFilter;
use std::io::{Read, Seek, SeekFrom};

/// Result of one attached read.
///
/// # Example
///
/// ```rust
/// use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};
/// use std::io::Cursor;
///
/// let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 2)])
///     .unwrap()
///     .with_window_size(3)
///     .unwrap()
///     .with_chunk_size(4)
///     .unwrap();
///
/// let mut attachment = filter.attach(Cursor::new(b"baac"));
/// let chunk = attachment.read_next().unwrap().unwrap();
/// assert_eq!(chunk.data, b"baac");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilteredChunk {
    /// Absolute byte offset of the first byte in `data`.
    pub offset: u64,
    /// Raw bytes read from the underlying source, including overlap bytes.
    pub data: Vec<u8>,
    /// Count of newly-read source bytes in this chunk, EXCLUDING the carried-over
    /// overlap already counted by the previous chunk. Callers tracking a byte
    /// budget must accumulate this, not `data.len()` (which double-counts the
    /// overlap and trips a `max_bytes` limit early).
    pub new_bytes: usize,
    /// Candidate ranges reported within this chunk.
    pub candidate_ranges: Vec<MatchWindow>,
}

/// Reader attachment that applies a [`ByteFrequencyFilter`] to each read chunk.
///
/// # Example
///
/// ```rust
/// use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};
/// use std::io::Cursor;
///
/// let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 2)])
///     .unwrap()
///     .with_window_size(3)
///     .unwrap();
///
/// let mut reader = filter.attach(Cursor::new(b"baaac"));
/// let chunk = reader.read_next().unwrap().unwrap();
/// assert!(!chunk.candidate_ranges.is_empty());
/// ```
#[derive(Debug)]
pub struct FileReadFilter<R> {
    reader: R,
    filter: ByteFrequencyFilter,
    carry: Vec<u8>,
    next_offset: u64,
    finished: bool,
    /// Reusable read scratch buffer. `read_next` fills this, copies its contents
    /// into the returned chunk's window, then keeps the allocation for the next
    /// call - avoiding a fresh `vec![0u8; chunk_size]` heap allocation on every
    /// chunk in the hot read loop.
    read_buf: Vec<u8>,
    /// Optional cap on the next read size. Used by `ByteFrequencyFilter::scan_file`
    /// to avoid reading past `max_bytes` on the final chunk.
    next_read_limit: Option<usize>,
    /// Optional kernel filter that emits skip decisions for this reader.
    kernel_filter: Option<KernelFilter>,
    /// Optional seek function pointer. Set when the reader is `Seek` so skip
    /// decisions can advance the reader past no-match regions. Non-seekable
    /// readers keep this as `None` and skip decisions are ignored rather than
    /// silently degrading to a slower path.
    seek_fn: Option<fn(&mut R, SeekFrom) -> std::io::Result<u64>>,
}

impl<R: Read> FileReadFilter<R> {
    /// Creates a new attached reader.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};
    /// use std::io::Cursor;
    ///
    /// let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
    ///     .unwrap();
    /// let reader = filter.attach(Cursor::new(b"hello"));
    /// ```
    #[must_use]
    pub fn new(reader: R, filter: ByteFrequencyFilter) -> Self {
        Self {
            reader,
            filter,
            carry: Vec::new(),
            next_offset: 0,
            finished: false,
            read_buf: Vec::new(),
            next_read_limit: None,
            kernel_filter: None,
            seek_fn: None,
        }
    }

    /// Creates a new attached reader that can seek, enabling kernel-filter skip decisions
    /// to advance the reader past regions that cannot contain matches.
    #[must_use]
    pub fn new_seekable(reader: R, filter: ByteFrequencyFilter) -> Self
    where
        R: Seek,
    {
        Self {
            reader,
            filter,
            carry: Vec::new(),
            next_offset: 0,
            finished: false,
            read_buf: Vec::new(),
            next_read_limit: None,
            kernel_filter: None,
            seek_fn: Some(<R as Seek>::seek),
        }
    }

    /// Attach a kernel filter that will emit skip decisions for this reader.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidConfiguration` if the reader is not seekable.
    pub fn set_kernel_filter(&mut self, filter: KernelFilter) -> Result<()> {
        if self.seek_fn.is_none() {
            return Err(Error::InvalidConfiguration {
                reason: "kernel filter cannot be attached to a non-seekable reader".to_string(),
                fix: "create the reader using attach_seekable to enable kernel filter skip decisions",
            });
        }
        self.kernel_filter = Some(filter);
        Ok(())
    }

    /// Returns the attached filter configuration.
    #[must_use]
    pub fn filter(&self) -> &ByteFrequencyFilter {
        &self.filter
    }

    /// Cap the next read to at most `limit` bytes, then clear the cap.
    ///
    /// Used by `ByteFrequencyFilter::scan_file` with a `max_bytes` budget so
    /// the final read does not over-request bytes and block on slow streams.
    pub fn set_next_read_limit(&mut self, limit: usize) {
        self.next_read_limit = Some(limit);
    }

    /// Reads the next chunk and returns candidate ranges, or `None` at EOF.
    ///
    /// On error, returns a tuple of (`partial_chunk`, error) so callers can
    /// access matches found before the failure.
    ///
    /// # Errors
    ///
    /// Returns `Error::ReadFailed` when the underlying reader returns an I/O error.
    pub fn read_next(
        &mut self,
    ) -> std::result::Result<Option<FilteredChunk>, (FilteredChunk, Error)> {
        if self.finished {
            return Ok(None);
        }

        // Poll the kernel filter for skip decisions ONLY when the reader is
        // seekable. If it is not seekable, the decisions are unusable (Law 10 -
        // no silent degrade to a slower scan) AND polling them would be pure
        // waste, so we do not poll at all. When seekable, iterate the borrowed
        // slice returned by `poll_skips` in place - the previous code copied it
        // into a fresh `Vec` on every single chunk read (Law 7 hot-path alloc),
        // even on the overwhelmingly common no-skip path where the slice is
        // empty. `poll_skips` borrows `self.kernel_filter`; the seek/carry/offset
        // fields it touches are disjoint, so the borrow is sound.
        if let Some(seek_fn) = self.seek_fn {
            if let Some(kf) = self.kernel_filter.as_mut() {
                for decision in kf.poll_skips() {
                    let skip_end = decision.file_offset.saturating_add(decision.skip_length);
                    if skip_end > self.next_offset {
                        match seek_fn(&mut self.reader, SeekFrom::Start(skip_end)) {
                            Ok(new_pos) => {
                                self.next_offset = new_pos;
                                self.carry.clear();
                            }
                            Err(source) => {
                                let carry_len = self.carry.len();
                                let chunk_offset =
                                    self.next_offset.saturating_sub(carry_len as u64);
                                let data = std::mem::take(&mut self.carry);
                                return Err((
                                    FilteredChunk {
                                        offset: chunk_offset,
                                        data,
                                        new_bytes: 0,
                                        candidate_ranges: Vec::new(),
                                    },
                                    Error::ReadFailed { source },
                                ));
                            }
                        }
                    }
                }
            }
        }

        // Reuse the scratch buffer across calls (retains its capacity) instead
        // of allocating `vec![0u8; chunk_size]` every chunk. `read` fills up to
        // buf.len() bytes, so it must be sized to the effective chunk size first.
        let read_size = self
            .next_read_limit
            .take()
            .unwrap_or(self.filter.chunk_size())
            .min(self.filter.chunk_size());
        self.read_buf.resize(read_size, 0);
        let bytes_read = loop {
            // Disjoint field borrow: `reader` and `read_buf` are distinct fields.
            match self.reader.read(&mut self.read_buf) {
                Ok(n) => break n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
                Err(source) => {
                    // Return the carried overlap as a partial chunk so the caller
                    // has the bytes seen so far. Matches inside the carry were
                    // already reported as part of the previous chunk.
                    let carry_len = self.carry.len();
                    let chunk_offset = self.next_offset.saturating_sub(carry_len as u64);
                    let data = std::mem::take(&mut self.carry);
                    return Err((
                        FilteredChunk {
                            offset: chunk_offset,
                            data,
                            new_bytes: 0,
                            candidate_ranges: Vec::new(),
                        },
                        Error::ReadFailed { source },
                    ));
                }
            }
        };
        if bytes_read == 0 {
            self.finished = true;
            return Ok(None);
        }
        self.read_buf.truncate(bytes_read);

        let carry_len = self.carry.len();
        let chunk_offset = self.next_offset.saturating_sub(carry_len as u64);
        let mut window = std::mem::take(&mut self.carry);
        window.extend_from_slice(&self.read_buf);

        let candidate_ranges = self
            .filter
            .matching_windows(&window)
            .into_iter()
            .map(|range| MatchWindow {
                offset: chunk_offset + range.offset,
                length: range.length,
            })
            .collect::<Vec<_>>();

        let keep = self
            .filter
            .window_size()
            .saturating_sub(1)
            .min(window.len());
        self.carry = window[window.len() - keep..].to_vec();
        self.next_offset = self.next_offset.saturating_add(bytes_read as u64);

        Ok(Some(FilteredChunk {
            offset: chunk_offset,
            data: window,
            new_bytes: bytes_read,
            candidate_ranges,
        }))
    }
}

#[cfg(test)]
mod tests {
    use crate::{ByteFrequencyFilter, ByteThreshold};
    use std::io::Cursor;

    #[test]
    fn read_next_new_bytes_sums_to_input_length_excluding_overlap() {
        // 16-byte input, window_size 4 (so 3 overlap bytes carry between chunks)
        // and chunk_size 5 forces several chunks. `data.len()` repeats the carry
        // each chunk and overcounts; `new_bytes` must sum to exactly the input.
        let input: &[u8] = b"abcdefghijklmnop";
        let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
            .unwrap()
            .with_window_size(4)
            .unwrap()
            .with_chunk_size(5)
            .unwrap();
        let mut reader = filter.attach(Cursor::new(input));

        let mut total_new = 0usize;
        let mut total_data = 0usize;
        let mut saw_overlap = false;
        while let Some(chunk) = reader.read_next().unwrap() {
            total_new += chunk.new_bytes;
            total_data += chunk.data.len();
            if chunk.data.len() > chunk.new_bytes {
                saw_overlap = true;
            }
        }

        assert_eq!(
            total_new,
            input.len(),
            "new_bytes must sum to the true input length"
        );
        assert!(
            total_data > input.len(),
            "data.len() sum ({total_data}) overcounts because of carried overlap"
        );
        assert!(
            saw_overlap,
            "expected at least one chunk to carry overlap bytes (data.len() > new_bytes)"
        );
    }

    #[test]
    fn read_next_returns_carry_on_error() {
        // Custom reader that returns bytes on the first read, then errors.
        struct FailAfterFirst {
            data: Vec<u8>,
            first: bool,
        }
        impl std::io::Read for FailAfterFirst {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if !self.first {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "simulated read failure",
                    ));
                }
                self.first = false;
                let n = buf.len().min(self.data.len());
                buf[..n].copy_from_slice(&self.data[..n]);
                Ok(n)
            }
        }

        // window_size=4, chunk_size=8, input 16 bytes. First read consumes 8 bytes
        // and leaves 3 carry bytes. The next read fails and must return those 3
        // carry bytes as the partial chunk data.
        let input = b"abcdefghijklmnop";
        let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
            .unwrap()
            .with_window_size(4)
            .unwrap()
            .with_chunk_size(8)
            .unwrap();
        let mut reader = filter.attach(FailAfterFirst {
            data: input.to_vec(),
            first: true,
        });

        let chunk = reader.read_next().unwrap().unwrap();
        assert_eq!(chunk.new_bytes, 8);

        let (partial, _err) = reader.read_next().unwrap_err();
        assert_eq!(partial.new_bytes, 0);
        assert_eq!(partial.data, b"fgh"); // last 3 bytes of first read
        assert_eq!(partial.offset, 5);   // offset of 'f' in the original stream
    }

    #[test]
    fn next_read_limit_clamps_final_chunk_size() {
        // Regression: scan_file used to read a full chunk before checking
        // max_bytes, which could over-read and block on slow streams. Verify
        // that set_next_read_limit caps the number of bytes requested by the
        // next read_next call.
        let input: &[u8] = b"abcdefghijklmnop"; // 16 bytes
        let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
            .unwrap()
            .with_window_size(4)
            .unwrap()
            .with_chunk_size(10)
            .unwrap();
        let mut reader = filter.attach(Cursor::new(input));

        // First read: full chunk of 10 bytes.
        let chunk1 = reader.read_next().unwrap().unwrap();
        assert_eq!(chunk1.new_bytes, 10);

        // Set a cap of 3 bytes for the next read; it must not exceed the cap.
        reader.set_next_read_limit(3);
        let chunk2 = reader.read_next().unwrap().unwrap();
        assert_eq!(chunk2.new_bytes, 3);

        // Verify the total input was consumed (10 + 3 + 3 = 16).
        reader.set_next_read_limit(3);
        let chunk3 = reader.read_next().unwrap().unwrap();
        assert_eq!(chunk3.new_bytes, 3);

        assert!(reader.read_next().unwrap().is_none());
    }

    #[test]
    fn reused_read_buffer_does_not_corrupt_chunk_data() {
        // Regression for loader.rs:108 (buffer reuse): read_next now keeps one
        // scratch buffer across calls instead of allocating per chunk. If a
        // shorter final read left stale bytes from a previous (larger) chunk,
        // the reassembled stream would differ from the input. Reassemble the
        // FRESH bytes of every chunk (the last new_bytes of data) and require
        // byte-exact equality with the input across many reuse cycles, including
        // a smaller trailing chunk.
        let input: &[u8] = b"0123456789ABCDEFGHIJKLM"; // 23 bytes, all distinct
        let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'0', 1)])
            .unwrap()
            .with_window_size(4)
            .unwrap()
            .with_chunk_size(5) // 5,5,5,5,3 -> reuse + a smaller final chunk
            .unwrap();
        let mut reader = filter.attach(Cursor::new(input));

        let mut reassembled = Vec::new();
        while let Some(chunk) = reader.read_next().unwrap() {
            let fresh_start = chunk.data.len() - chunk.new_bytes;
            reassembled.extend_from_slice(&chunk.data[fresh_start..]);
        }
        assert_eq!(
            reassembled, input,
            "reused buffer corrupted the stream (stale bytes leaked between chunks)"
        );
    }

    #[test]
    fn kernel_filter_skip_decisions_move_reader_past_skipped_region() {
        use crate::kernel::{KernelFilter, SkipDecision};

        // Input: 20 bytes. Region [3,7) = "SKIP" is reported by the kernel filter
        // as a no-match region; the seekable reader should start the first chunk
        // at offset 7 instead of 0.
        let input: &[u8] = b"aaaSKIPaaaaMATCHaaaa";
        let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 4)])
            .unwrap()
            .with_window_size(4)
            .unwrap()
            .with_chunk_size(8)
            .unwrap();

        let kernel_filter = KernelFilter::with_test_skips(
            vec![ByteThreshold::new(b'a', 4)],
            vec![SkipDecision {
                inode: 0,
                file_offset: 3,
                skip_length: 4,
            }],
        );

        let mut reader = filter.attach_seekable(Cursor::new(input));
        reader.set_kernel_filter(kernel_filter).unwrap();

        let chunk = reader.read_next().unwrap().unwrap();
        assert_eq!(chunk.offset, 7, "first chunk must start after the skipped region");
        assert_eq!(chunk.new_bytes, 8);
        // The chunk should begin at the first byte after the skipped region.
        assert_eq!(
            chunk.data,
            b"aaaaMATC",
            "data must start at the byte following the skipped region"
        );
    }

    #[test]
    fn non_seekable_reader_rejects_kernel_filter_attachment() {
        use crate::kernel::{KernelFilter, SkipDecision};

        let input: &[u8] = b"aaaSKIPaaaaMATCHaaaa";
        let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 4)])
            .unwrap()
            .with_window_size(4)
            .unwrap()
            .with_chunk_size(8)
            .unwrap();

        let kernel_filter = KernelFilter::with_test_skips(
            vec![ByteThreshold::new(b'a', 4)],
            vec![SkipDecision {
                inode: 0,
                file_offset: 3,
                skip_length: 4,
            }],
        );

        let mut reader = filter.attach(Cursor::new(input));
        assert!(
            reader.set_kernel_filter(kernel_filter).is_err(),
            "set_kernel_filter on non-seekable reader must return error"
        );
    }

    #[test]
    fn kernel_filter_skip_clears_carry_and_prevents_discontinuity_matches() {
        use crate::kernel::{KernelFilter, SkipDecision};
        use std::io::Cursor;

        // Input: 40 bytes
        // 0..8:   b"0123xxaa"
        // 8..16:  b"SKIP1111" (skipped by filter 1 [8, 16))
        // 16..24: b"aaxx4567" (read as chunk 1 at offset 16; carry = b"567")
        // 24..32: b"SKIP2222" (skipped by filter 2 [24, 32))
        // 32..40: b"89012345" (read as chunk 2 at offset 32)
        // If carry (b"567") were NOT cleared on skip decision 2:
        // - chunk 2 offset would be 32 - 3 = 29 (WRONG)
        // - chunk 2 data would be b"56789012345" (WRONG)
        // With carry cleared:
        // - chunk 2 offset is 32
        // - chunk 2 data is b"89012345"
        let mut input = Vec::new();
        input.extend_from_slice(b"0123xxaa"); // 0..8
        input.extend_from_slice(b"SKIP1111"); // 8..16
        input.extend_from_slice(b"aaxx4567"); // 16..24
        input.extend_from_slice(b"SKIP2222"); // 24..32
        input.extend_from_slice(b"89012345"); // 32..40

        let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 4)])
            .unwrap()
            .with_window_size(4)
            .unwrap()
            .with_chunk_size(8)
            .unwrap();

        let kf1 = KernelFilter::with_test_skips(
            vec![ByteThreshold::new(b'a', 4)],
            vec![SkipDecision {
                inode: 0,
                file_offset: 8,
                skip_length: 8,
            }],
        );

        let mut reader = filter.attach_seekable(Cursor::new(&input[..]));
        reader.set_kernel_filter(kf1).unwrap();

        // Chunk 1: decision 1 skips 8..16; reads 16..24 (b"aaxx4567").
        let chunk1 = reader.read_next().unwrap().unwrap();
        assert_eq!(chunk1.offset, 16);
        assert_eq!(chunk1.data, b"aaxx4567");

        // Now attach decision 2 for offset 24..32.
        let kf2 = KernelFilter::with_test_skips(
            vec![ByteThreshold::new(b'a', 4)],
            vec![SkipDecision {
                inode: 0,
                file_offset: 24,
                skip_length: 8,
            }],
        );
        reader.set_kernel_filter(kf2).unwrap();

        // Chunk 2: decision 2 skips 24..32; carry from chunk 1 (b"567") must be cleared!
        let chunk2 = reader.read_next().unwrap().unwrap();
        assert_eq!(
            chunk2.offset, 32,
            "chunk offset must be 32 after skip, not 32 - carry_len"
        );
        assert_eq!(chunk2.data, b"89012345");
        assert!(
            chunk2.candidate_ranges.is_empty(),
            "no match must straddle the skip boundary"
        );
    }
    #[test]
    fn kernel_filter_overlapping_skip_decision_advances_reader_when_skip_end_exceeds_next_offset() {
        use crate::kernel::{KernelFilter, SkipDecision};
        use std::io::Cursor;

        // Input: 64 bytes
        // Offsets 0..16: chunk 1 data
        // Offsets 16..32: skipped by decision (file_offset: 10, skip_length: 22 -> skip_end: 32)
        // Notice file_offset (10) < next_offset (16), but skip_end (32) > next_offset (16).
        // Offsets 32..48: chunk 2 data
        let mut input = Vec::new();
        input.extend_from_slice(b"0123456789abcdef"); // 0..16
        input.extend_from_slice(b"SKIP_REGION_____"); // 16..32
        input.extend_from_slice(b"CHUNK2_DATA_____"); // 32..48
        input.extend_from_slice(b"TRAILING_DATA___"); // 48..64

        let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
            .unwrap()
            .with_window_size(4)
            .unwrap()
            .with_chunk_size(16)
            .unwrap();

        let mut reader = filter.attach_seekable(Cursor::new(&input[..]));

        // Read chunk 1 (offsets 0..16); next_offset becomes 16
        let chunk1 = reader.read_next().unwrap().unwrap();
        assert_eq!(chunk1.offset, 0);
        assert_eq!(chunk1.data, b"0123456789abcdef");

        // Attach a skip decision starting at 10 (before next_offset 16) but extending to 32
        let kf = KernelFilter::with_test_skips(
            vec![ByteThreshold::new(b'a', 1)],
            vec![SkipDecision {
                inode: 0,
                file_offset: 10,
                skip_length: 22, // 10 + 22 = 32
            }],
        );
        reader.set_kernel_filter(kf).unwrap();

        // Chunk 2: must apply the skip decision because skip_end (32) > next_offset (16),
        // seeking to offset 32 and reading b"CHUNK2_DATA_____"
        let chunk2 = reader.read_next().unwrap().unwrap();
        assert_eq!(
            chunk2.offset, 32,
            "chunk offset must advance to 32 despite file_offset being < 16"
        );
        assert_eq!(chunk2.data, b"CHUNK2_DATA_____");
    }
}
