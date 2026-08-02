# Changelog

## [0.1.3] - 2026-08-02

### Fixed
- README examples were stale or did not compile against the real API. They are rewritten and wired as doctests, so documentation drift now fails `cargo test`.

## [0.1.2] - 2026-07-30

### Fixed
- `cargo clippy --all-targets` failed: the manifest-level `unwrap_used`/`expect_used` deny also applied to test builds. Test code now opts out via `#![cfg_attr(test, allow(...))]` in the crate root and an allow header in `tests/shard_s_perf_pmg_edge.rs`, matching the convention used by the other test targets.

## [0.1.0] - 2026-04-12

### Added
- Initial release of ebpfsieve.
