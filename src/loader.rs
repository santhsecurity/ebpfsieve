//! File reading and chunk loading.

use crate::error::Error;
use crate::map::MatchWindow;
use crate::program::ByteFrequencyFilter;
use std::io::Read;

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
        }
    }

    /// Returns the attached filter configuration.
    #[must_use]
    pub fn filter(&self) -> &ByteFrequencyFilter {
        &self.filter
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

        let mut buf = vec![0u8; self.filter.chunk_size()];
        let bytes_read = loop {
            match self.reader.read(&mut buf) {
                Ok(n) => break n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
                Err(source) => {
                    // Return partial results alongside the error
                    let empty_chunk = FilteredChunk {
                        offset: self.next_offset,
                        data: Vec::new(),
                        candidate_ranges: Vec::new(),
                    };
                    return Err((empty_chunk, Error::ReadFailed { source }));
                }
            }
        };
        if bytes_read == 0 {
            self.finished = true;
            return Ok(None);
        }
        buf.truncate(bytes_read);

        let carry_len = self.carry.len();
        let chunk_offset = self.next_offset.saturating_sub(carry_len as u64);
        let mut window = std::mem::take(&mut self.carry);
        window.extend_from_slice(&buf);

        let candidate_ranges = self
            .filter
            .matching_windows(&window)
            .into_iter()
            .filter(|range| {
                usize::try_from(range.offset)
                    .map(|offset| offset.saturating_add(range.length) > carry_len)
                    .unwrap_or(true)
            })
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
            candidate_ranges,
        }))
    }
}
