# ebpfsieve — Technical Spec

## Overview

Byte-frequency filtering that can be attached to file reads.  `ebpfsieve` provides a small, production-usable filtering primitive for read-heavy pipelines: define required byte-frequency thresholds, attach the filter to a reader, and scan file chunks for windows that might contain a match before handing them to a more expensive verifier.  On Linux, optional classic BPF socket filters (see the [`kernel`] module and the `socket-bpf` feature) can prefilter packet payloads before userspace work.  # Example  ```rust use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};  let filter = ByteFrequencyFilter::new([ ByteThreshold::new(b'a', 3), ])? .with_window_size(5)?;  let matches = filter.matching_windows(b"xyzaaaxyz"); // "yzaaa" at offset 1 has a=3 → first match assert_eq!(matches[0].offset, 1); # Ok::<(), ebpfsieve::Error>(()) ```

## Architecture

The crate is organized into the following public modules:

- `error`
- `kernel`
- `loader`
- `map`
- `program`

## Guarantees

- `#![forbid(unsafe_code)]` where applicable; see `src/lib.rs` for the exact lint preamble.
- All public types have doc comments.
- Error messages are actionable where applicable.

## Public API Summary

Key entry points are exported from `src/lib.rs` via `pub mod` and `pub use` re-exports.
Consult the module-level documentation in each source file for function signatures and usage examples.

## Error Handling

- `Error`
