# Changelog

## [0.1.5] - 2026-08-07

### Fixed
- Fixed kernel skip decision boundary evaluation in `FileReadFilter`: skip decisions starting before `next_offset` but ending past `next_offset` (`skip_end > next_offset`) now correctly advance the reader and clear carry overlap instead of being silently dropped.
- Added `attach_socket_ebpf_to_fd` fallback method when compiling without `socket-bpf` or on non-Linux platforms, returning `Error::EbpfUnavailable` with actionable guidance rather than failing compilation.
- Audited eBPF sieve compile/load/attach, ring buffer fail-closed error propagation (`open_ring_buffer`), and socket filter BPF instruction bounds checking.

## [0.1.4] - 2026-08-07

- Clear carry after successful kernel skip-seek so matches cannot span skipped regions.
- `set_kernel_filter` fails closed on non-seekable readers (`Result`).
- Zero-alloc threshold bitset + O(1) MatchWindowIter parity with matching_windows.
- Authors/status metadata updated (`stable`).


## [0.1.3] - 2026-08-02

### Fixed
- README examples were stale or did not compile against the real API. They are rewritten and wired as doctests, so documentation drift now fails `cargo test`.

## [0.1.2] - 2026-07-30

### Fixed
- `cargo clippy --all-targets` failed: the manifest-level `unwrap_used`/`expect_used` deny also applied to test builds. Test code now opts out via `#![cfg_attr(test, allow(...))]` in the crate root and an allow header in `tests/shard_s_perf_pmg_edge.rs`, matching the convention used by the other test targets.

## [0.1.0] - 2026-04-12

### Added
- Initial release of ebpfsieve.
