#![warn(missing_docs)]
//! Byte-frequency filtering that can be attached to file reads.
//!
//! `ebpfsieve` provides a small, production-usable filtering primitive for
//! read-heavy pipelines: define required byte-frequency thresholds, attach the
//! filter to a reader, and scan file chunks for windows that might contain a
//! match before handing them to a more expensive verifier.
//!
//! When running on Linux, the filter can be offloaded to an eBPF program
//! (see the [`kernel`] module) which runs inside the kernel's VFS layer. This
//! allows skipping data before it is even copied from the kernel to userspace.
//!
//! # Example
//!
//! ```rust
//! use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};
//!
//! let filter = ByteFrequencyFilter::new([
//!     ByteThreshold::new(b'a', 3),
//! ])?
//! .with_window_size(5)?;
//!
//! let matches = filter.matching_windows(b"xyzaaaxyz");
//! // "yzaaa" at offset 1 has a=3 → first match
//! assert_eq!(matches[0].offset, 1);
//! # Ok::<(), ebpfsieve::Error>(())
//! ```

#![deny(unsafe_code)]
#![allow(clippy::module_name_repetitions, clippy::missing_errors_doc)]

pub mod error;
mod iter;
pub mod kernel;
pub mod loader;
pub mod map;
pub mod program;

pub use error::{Error, Result};
pub use iter::MatchWindowIter;
pub use loader::{FileReadFilter, FilteredChunk};
pub use map::{ByteThreshold, MatchWindow};
pub use program::ByteFrequencyFilter;

#[cfg(all(target_os = "linux", feature = "socket-bpf"))]
pub use kernel::SocketFilterProgram;
