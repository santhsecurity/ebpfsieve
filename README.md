# ebpfsieve

Byte-frequency prefilter for read-heavy scanning pipelines, with optional eBPF offload.

## What it does

`ebpfsieve` slides a fixed-size window over byte streams and reports candidate windows where all required byte-count thresholds are met. The idea is to cheaply reject data before handing it to a more expensive verifier.

- **Userspace filtering** — pure Rust, no dependencies on kernel features.
- **Lazy iteration** — `matching_windows_iter` yields matches one at a time without allocating a `Vec`.
- **Chunked readers** — attach the filter to any `Read` impl and get per-chunk candidate ranges with automatic carry-over across chunk boundaries.
- **Optional eBPF** — on Linux with the right features enabled, compile and load classic BPF socket filters or `aya`-based `fentry/vfs_read` probes.

## Quick start

```rust
use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};

let filter = ByteFrequencyFilter::new([
    ByteThreshold::new(b'a', 3),
])?
.with_window_size(5)?;

let matches = filter.matching_windows(b"xyzaaaxyz");
assert_eq!(matches[0].offset, 1); // "yzaaa"
```

## Filtering model

A `ByteFrequencyFilter` is built from one or more `ByteThreshold` values. A window matches when **every** threshold is satisfied. Counts are maintained in a `u16` histogram with saturating arithmetic, so very long windows are safe from overflow.

## Reading files in chunks

```rust
use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};
use std::fs::File;

let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 2)])?
    .with_window_size(64)?
    .with_chunk_size(4096)?;

let mut file = File::open("data.bin")?;
let matches = filter.scan_file(&mut file, Some(1_000_000))?;
```

## Lazy iteration

For internet-scale scanning, avoid collecting all matches into a `Vec`:

```rust
let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)])?;
let mut iter = filter.matching_windows_iter(b"banana");
if let Some(first) = iter.next() {
    println!("first match at offset {}", first.offset);
}
```

## Optional features

- **`serde`** — load filter rules from TOML with `from_toml_str` / `from_toml_file`.
- **`socket-bpf`** — compile and load classic `BPF_PROG_TYPE_SOCKET_FILTER` programs via `ebpfkit` (Linux only).
- **`kernel-bpf`** — load `aya`-based `fentry/vfs_read` probes (Linux ≥ 5.8, BTF, root required).

## Errors

All fallible operations return `ebpfsieve::Result<T>`. Errors carry actionable messages, for example:

```text
invalid filter configuration: window_size cannot be zero. Fix: provide a window_size of at least 1
```

## License

MIT
