//! Byte frequency filtering program.

#[cfg(feature = "serde")]
use std::fs;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{Error, Result};
use crate::iter::MatchWindowIter;
use crate::loader::FileReadFilter;
use crate::map::{ByteThreshold, MatchWindow};

/// Byte-frequency filter that rejects windows lacking required byte counts.
///
/// Use `from_toml_file` or `from_toml_str` to load filter rules dynamically.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ByteFrequencyFilter {
    thresholds: Vec<ByteThreshold>,
    window_size: usize,
    chunk_size: usize,
    max_matches: usize,
}

impl ByteFrequencyFilter {
    /// Creates a filter from one or more byte thresholds.
    ///
    /// The default window size is 4096 bytes and the default read chunk size is
    /// 64 KiB.
    pub fn new(thresholds: impl IntoIterator<Item = ByteThreshold>) -> Result<Self> {
        let thresholds = thresholds.into_iter().collect::<Vec<_>>();
        if thresholds.is_empty() {
            return Err(Error::InvalidConfiguration {
                reason: "at least one byte threshold is required".to_string(),
                fix: "provide one or more ByteThreshold values",
            });
        }
        if thresholds.iter().any(|threshold| threshold.min_count == 0) {
            return Err(Error::InvalidConfiguration {
                reason: "threshold counts must be greater than zero".to_string(),
                fix: "use ByteThreshold::new(byte, count) with count >= 1",
            });
        }

        Ok(Self {
            thresholds,
            window_size: 4096,
            chunk_size: 64 * 1024,
            max_matches: 1_000_000,
        })
    }

    /// Sets the sliding-window size used for matching.
    ///
    /// A larger window lowers false negatives for spread-out signatures, while
    /// a smaller window gives tighter candidate ranges.
    ///
    /// # Errors
    ///
    /// Returns an error if `window_size` is 0.
    pub fn with_window_size(mut self, window_size: usize) -> Result<Self> {
        if window_size == 0 {
            return Err(Error::InvalidConfiguration {
                reason: "window_size cannot be zero".to_string(),
                fix: "provide a window_size of at least 1",
            });
        }
        self.window_size = window_size;
        Ok(self)
    }

    /// Sets the chunk size used by attached readers.
    ///
    /// # Errors
    ///
    /// Returns an error if `chunk_size` is 0.
    pub fn with_chunk_size(mut self, chunk_size: usize) -> Result<Self> {
        if chunk_size == 0 {
            return Err(Error::InvalidConfiguration {
                reason: "chunk_size cannot be zero".to_string(),
                fix: "provide a chunk_size of at least 1",
            });
        }
        self.chunk_size = chunk_size;
        Ok(self)
    }

    /// Sets the maximum number of matches to collect.
    ///
    /// This prevents unbounded memory growth when scanning files with infinite
    /// streams (e.g., `/dev/zero`). Default is 1,000,000.
    #[must_use]
    pub fn with_max_matches(mut self, max_matches: usize) -> Self {
        self.max_matches = max_matches;
        self
    }

    /// Returns the configured byte thresholds.
    #[must_use]
    pub fn thresholds(&self) -> &[ByteThreshold] {
        &self.thresholds
    }

    /// Returns the sliding-window size in bytes.
    #[must_use]
    pub fn window_size(&self) -> usize {
        self.window_size
    }

    /// Returns the attached-reader chunk size in bytes.
    #[must_use]
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Returns the maximum number of matches to collect.
    #[must_use]
    pub fn max_matches(&self) -> usize {
        self.max_matches
    }

    /// Returns whether a single byte slice satisfies the filter.
    #[must_use]
    pub fn matches_bytes(&self, bytes: &[u8]) -> bool {
        let mut counts = [0u16; 256];
        for &byte in bytes {
            counts[byte as usize] = counts[byte as usize].saturating_add(1);
        }
        self.thresholds
            .iter()
            .all(|threshold| counts[threshold.byte as usize] >= threshold.min_count)
    }

    /// Returns every matching window in a byte slice.
    ///
    /// Stops collecting matches once `max_matches` is reached to prevent
    /// unbounded memory growth.
    #[must_use]
    pub fn matching_windows(&self, bytes: &[u8]) -> Vec<MatchWindow> {
        if bytes.is_empty() || self.max_matches == 0 {
            return Vec::new();
        }

        let window = self.window_size.min(bytes.len());
        let mut counts = [0u16; 256];
        for &byte in &bytes[..window] {
            counts[byte as usize] = counts[byte as usize].saturating_add(1);
        }

        // Track satisfied threshold count for O(1) per-position checking.
        // Instead of checking all k thresholds every position, only recheck
        // the thresholds for the byte that changed (entered/left the window).
        let mut satisfied = 0usize;
        let total_thresholds = self.thresholds.len();
        // Map: byte value → list of threshold indices that reference this byte
        let mut byte_to_thresholds = [const { Vec::new() }; 256];
        for (i, t) in self.thresholds.iter().enumerate() {
            byte_to_thresholds[t.byte as usize].push(i);
        }
        let mut threshold_met = vec![false; total_thresholds];
        for (i, t) in self.thresholds.iter().enumerate() {
            if counts[t.byte as usize] >= t.min_count {
                threshold_met[i] = true;
                satisfied += 1;
            }
        }

        let mut matches = Vec::new();
        if satisfied == total_thresholds {
            matches.push(MatchWindow {
                offset: 0,
                length: window,
            });
            if matches.len() >= self.max_matches {
                return matches;
            }
        }

        if bytes.len() > window {
            for start in 1..=bytes.len() - window {
                let removed = bytes[start - 1] as usize;
                let added = bytes[start + window - 1] as usize;
                counts[removed] = counts[removed].saturating_sub(1);
                counts[added] = counts[added].saturating_add(1);

                // Only recheck thresholds affected by the changed bytes.
                for &ti in &byte_to_thresholds[removed] {
                    let was_met = threshold_met[ti];
                    let now_met =
                        counts[self.thresholds[ti].byte as usize] >= self.thresholds[ti].min_count;
                    if was_met && !now_met {
                        satisfied -= 1;
                        threshold_met[ti] = false;
                    }
                }
                for &ti in &byte_to_thresholds[added] {
                    let was_met = threshold_met[ti];
                    let now_met =
                        counts[self.thresholds[ti].byte as usize] >= self.thresholds[ti].min_count;
                    if !was_met && now_met {
                        satisfied += 1;
                        threshold_met[ti] = true;
                    }
                }

                if satisfied == total_thresholds {
                    matches.push(MatchWindow {
                        offset: start as u64,
                        length: window,
                    });
                    if matches.len() >= self.max_matches {
                        break;
                    }
                }
            }
        }

        matches
    }

    /// Attaches the filter to an arbitrary reader.
    #[must_use]
    pub fn attach<R: Read>(self, reader: R) -> FileReadFilter<R> {
        FileReadFilter::new(reader, self)
    }

    /// Scans an already-open file from its current position.
    ///
    /// Returns partial matches even if a read error occurs mid-stream.
    ///
    /// The optional `max_bytes` parameter limits how many bytes to read from the
    /// file. This prevents excessive memory usage when scanning very large files.
    /// Pass `None` to read until EOF (default for backward compatibility).
    pub fn scan_file(&self, file: &mut File, max_bytes: Option<u64>) -> Result<Vec<MatchWindow>> {
        // Track offset internally instead of using stream_position() to support
        // unseekable files (pipes, /dev/stdin) that would fail with ESPIPE.
        let mut attachment = self.clone().attach(file);
        let mut matches = Vec::new();
        let mut bytes_read_total: u64 = 0;
        loop {
            // Check byte limit before reading next chunk
            if let Some(limit) = max_bytes {
                if bytes_read_total >= limit {
                    break;
                }
            }
            match attachment.read_next() {
                Ok(None) => break,
                Ok(Some(chunk)) => {
                    bytes_read_total += chunk.data.len() as u64;
                    matches.extend(chunk.candidate_ranges);
                    // Check if we've reached max_matches
                    if matches.len() >= self.max_matches {
                        matches.truncate(self.max_matches);
                        break;
                    }
                }
                Err((partial, err)) => {
                    matches.extend(partial.candidate_ranges);
                    return Err(err);
                }
            }
        }
        Ok(matches)
    }

    /// Loads a `ByteFrequencyFilter` configuration from a TOML string.
    ///
    /// The TOML format expects an array of `thresholds`, each specifying `byte` (as an integer 0-255)
    /// and `min_count`. Optionally `window_size` and `chunk_size` and `max_matches` can be specified.
    #[cfg(feature = "serde")]
    pub fn from_toml_str(toml_content: &str) -> Result<Self> {
        #[derive(serde::Deserialize)]
        struct TomlConfig {
            thresholds: Vec<TomlThreshold>,
            window_size: Option<usize>,
            chunk_size: Option<usize>,
            max_matches: Option<usize>,
        }
        #[derive(serde::Deserialize)]
        struct TomlThreshold {
            byte: u8,
            min_count: u16,
        }

        let config: TomlConfig =
            toml::from_str(toml_content).map_err(|e| Error::InvalidConfiguration {
                reason: format!("Failed to parse TOML configuration: {e}"),
                fix: "Ensure the TOML file follows the expected schema with [[thresholds]] array.",
            })?;

        let thresholds: Vec<ByteThreshold> = config
            .thresholds
            .into_iter()
            .map(|t| ByteThreshold::new(t.byte, t.min_count))
            .collect();

        let mut filter = Self::new(thresholds)?;
        if let Some(w) = config.window_size {
            filter = filter.with_window_size(w)?;
        }
        if let Some(c) = config.chunk_size {
            filter = filter.with_chunk_size(c)?;
        }
        if let Some(m) = config.max_matches {
            filter = filter.with_max_matches(m);
        }

        Ok(filter)
    }

    /// Loads a `ByteFrequencyFilter` configuration from a TOML file.
    #[cfg(feature = "serde")]
    pub fn from_toml_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(|source| Error::ReadFailed { source })?;
        Self::from_toml_str(&content)
    }

    /// Opens and scans a file from the beginning.
    ///
    /// The optional `max_bytes` parameter limits how many bytes to read from the
    /// file. Pass `None` to read until EOF (default for backward compatibility).
    pub fn scan_path(
        &self,
        path: impl AsRef<Path>,
        max_bytes: Option<u64>,
    ) -> Result<Vec<MatchWindow>> {
        let mut file = File::open(path).map_err(|source| Error::ReadFailed { source })?;
        file.seek(SeekFrom::Start(0))
            .map_err(|source| Error::ReadFailed { source })?;
        self.scan_file(&mut file, max_bytes)
    }

    /// Returns an iterator over matching windows instead of collecting into Vec.
    /// For internet-scale scanning, this avoids allocating millions of `MatchWindow`
    /// structs when only a few are needed (e.g., first match for --quiet mode).
    #[must_use]
    pub fn matching_windows_iter<'a>(&'a self, bytes: &'a [u8]) -> MatchWindowIter<'a> {
        MatchWindowIter::new(self, bytes)
    }

    pub(crate) fn window_matches(&self, counts: &[u16; 256]) -> bool {
        self.thresholds
            .iter()
            .all(|threshold| counts[threshold.byte as usize] >= threshold.min_count)
    }

    /// Loads a JIT classic BPF socket filter and attaches it to `fd` via `SO_ATTACH_BPF`.
    ///
    /// Available on Linux only when the `socket-bpf` feature is enabled.
    /// Returns [`Error::EbpfUnavailable`] when not running as UID 0
    /// (typical `bpf(BPF_PROG_LOAD)` requirement) or when prerequisites are not met.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};
    /// use std::net::UdpSocket;
    /// use std::os::unix::io::AsRawFd;
    ///
    /// let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 1)]).unwrap();
    /// let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    /// let _ = filter.attach_socket_ebpf_to_fd(sock.as_raw_fd());
    /// ```
    #[cfg(all(target_os = "linux", feature = "socket-bpf"))]
    pub fn attach_socket_ebpf_to_fd(&self, fd: std::os::unix::io::RawFd) -> Result<()> {
        match crate::kernel::SocketFilterProgram::try_load(self)? {
            None => Err(Error::EbpfUnavailable {
                reason: "BPF_PROG_LOAD requires superuser (effective UID 0) on this kernel",
                fix: "run as root or use userspace ByteFrequencyFilter only",
            }),
            Some(prog) => prog.attach_to_fd(fd),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]
mod tests {
    use super::*;
    use crate::map::{ByteThreshold, MatchWindow};
    use std::io::Cursor;

    #[test]
    fn test_byte_threshold_new() {
        let t = ByteThreshold::new(b'x', 42);
        assert_eq!(t.byte, b'x');
        assert_eq!(t.min_count, 42);
    }

    #[test]
    fn test_filter_getters() {
        let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
            .unwrap()
            .with_window_size(1024)
            .unwrap()
            .with_chunk_size(2048)
            .unwrap();

        assert_eq!(filter.thresholds(), &[ByteThreshold::new(b'a', 1)]);
        assert_eq!(filter.window_size(), 1024);
        assert_eq!(filter.chunk_size(), 2048);
        assert_eq!(filter.max_matches(), 1_000_000);
    }

    #[test]
    fn test_zero_window_size_is_rejected() {
        let result = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
            .unwrap()
            .with_window_size(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_zero_chunk_size_is_rejected() {
        let result = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
            .unwrap()
            .with_chunk_size(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_matches_limit() {
        let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
            .unwrap()
            .with_window_size(1)
            .unwrap()
            .with_max_matches(5);

        // "aaaaa" has 5 'a's, each as a window of size 1
        let matches = filter.matching_windows(b"aaaaa");
        assert_eq!(matches.len(), 5);

        // Same data but with max_matches=3
        let filter_limited = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])
            .unwrap()
            .with_window_size(1)
            .unwrap()
            .with_max_matches(3);
        let matches_limited = filter_limited.matching_windows(b"aaaaa");
        assert_eq!(matches_limited.len(), 3);
    }

    #[test]
    fn test_matches_bytes() {
        let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 2)]).unwrap();
        assert!(filter.matches_bytes(b"aab"));
        assert!(!filter.matches_bytes(b"ab"));
    }

    #[test]
    fn matching_windows_slide_correctly() {
        let filter =
            ByteFrequencyFilter::new([ByteThreshold::new(b'e', 2), ByteThreshold::new(b'r', 2)])
                .unwrap()
                .with_window_size(5)
                .unwrap();

        // "xxerrerxx" with window=5, needs e≥2 AND r≥2:
        // offset 1: "xerre" → x=1,e=2,r=2 → MATCH
        // offset 2: "errer" → e=2,r=2 → MATCH
        // offset 3: "rrerx" → r=2,e=1 → no (e<2)
        let matches = filter.matching_windows(b"xxerrerxx");
        assert_eq!(
            matches,
            vec![
                MatchWindow {
                    offset: 1,
                    length: 5
                },
                MatchWindow {
                    offset: 2,
                    length: 5
                },
            ]
        );
    }

    #[test]
    fn attachment_reports_cross_chunk_match() {
        let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 2)])
            .unwrap()
            .with_window_size(3)
            .unwrap()
            .with_chunk_size(2)
            .unwrap();
        let mut attachment = filter.clone().attach(Cursor::new(b"baac".to_vec()));
        assert_eq!(attachment.filter(), &filter);

        let first = match attachment.read_next() {
            Ok(Some(chunk)) => chunk,
            Ok(None) => panic!("expected first chunk"),
            Err((_, e)) => panic!("unexpected error: {:?}", e),
        };
        assert!(first.candidate_ranges.is_empty());

        // "baac" with chunk=2, window=3, needs a≥2:
        // Chunk 2 combines carry "ba" + new "ac" = "baac"
        // Window "baa" at offset 0: a=2 → MATCH (spans carry into new data)
        // Window "aac" at offset 1: a=2 → MATCH
        let second = match attachment.read_next() {
            Ok(Some(chunk)) => chunk,
            Ok(None) => panic!("expected second chunk"),
            Err((_, e)) => panic!("unexpected error: {:?}", e),
        };
        assert_eq!(
            second.candidate_ranges,
            vec![
                MatchWindow {
                    offset: 0,
                    length: 3
                },
                MatchWindow {
                    offset: 1,
                    length: 3
                },
            ]
        );
    }

    #[test]
    fn empty_thresholds_are_rejected() {
        assert!(ByteFrequencyFilter::new([]).is_err());
    }

    #[test]
    fn zero_count_thresholds_are_rejected() {
        assert!(ByteFrequencyFilter::new([ByteThreshold::new(b'a', 0)]).is_err());
    }

    #[test]
    fn test_scan_file_and_path() {
        let temp_path = std::env::temp_dir().join("ebpfsieve_test_file.txt");
        std::fs::write(&temp_path, b"xxerrerxx").unwrap();

        let filter =
            ByteFrequencyFilter::new([ByteThreshold::new(b'e', 2), ByteThreshold::new(b'r', 2)])
                .unwrap()
                .with_window_size(5)
                .unwrap()
                .with_chunk_size(4)
                .unwrap();

        let mut f = std::fs::File::open(&temp_path).unwrap();
        let matches = filter.scan_file(&mut f, None).unwrap();
        assert_eq!(
            matches,
            vec![
                MatchWindow {
                    offset: 1,
                    length: 5
                },
                MatchWindow {
                    offset: 2,
                    length: 5
                },
            ]
        );

        let path_matches = filter.scan_path(&temp_path, None).unwrap();
        assert_eq!(path_matches, matches);

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_scan_file_with_max_bytes() {
        let temp_path = std::env::temp_dir().join("ebpfsieve_test_max_bytes.txt");
        // Write padding, then a unique pattern ("aaabbb"), then more padding
        // Filter requires 3 'a's and 3 'b's in a 6-byte window
        let mut content = vec![b'x'; 100];
        content.extend_from_slice(b"aaabbb"); // Unique pattern at offset 100
        content.extend_from_slice(&[b'x'; 100]);
        std::fs::write(&temp_path, &content).unwrap();

        let filter =
            ByteFrequencyFilter::new([ByteThreshold::new(b'a', 3), ByteThreshold::new(b'b', 3)])
                .unwrap()
                .with_window_size(6)
                .unwrap()
                .with_chunk_size(64)
                .unwrap();

        // Scan only first 50 bytes - should not reach the pattern at offset 100
        let mut f = std::fs::File::open(&temp_path).unwrap();
        let matches = filter.scan_file(&mut f, Some(50)).unwrap();
        assert_eq!(
            matches.len(),
            0,
            "Expected 0 matches when scanning 50 bytes"
        );

        // Scan first 110 bytes - should find the pattern at offset 100
        let mut f = std::fs::File::open(&temp_path).unwrap();
        let matches = filter.scan_file(&mut f, Some(110)).unwrap();
        assert_eq!(matches.len(), 1, "Expected 1 match when scanning 110 bytes");
        assert_eq!(matches[0].offset, 100);

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_matching_windows_iter() {
        let filter =
            ByteFrequencyFilter::new([ByteThreshold::new(b'e', 2), ByteThreshold::new(b'r', 2)])
                .unwrap()
                .with_window_size(5)
                .unwrap();

        let iter = filter.matching_windows_iter(b"xxerrerxx");
        let matches: Vec<_> = iter.collect();
        assert_eq!(
            matches,
            vec![
                MatchWindow {
                    offset: 1,
                    length: 5
                },
                MatchWindow {
                    offset: 2,
                    length: 5
                },
            ]
        );
    }
}
