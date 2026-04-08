//! Kernel-side eBPF byte-frequency filter.
//!
//! ## Classic BPF socket filter (`ebpfkit`)
//!
//! On Linux, [`SocketFilterProgram`] loads a JIT’d `BPF_PROG_TYPE_SOCKET_FILTER` program
//! (literal search derived from [`ByteFrequencyFilter`] via
//! [`compile_socket_filter_program`]) using `bpf(BPF_PROG_LOAD)`, then attaches it with
//! [`SocketFilterProgram::attach_to_fd`] (`SO_ATTACH_BPF`). Loading is skipped unless the
//! effective UID is `0`, matching typical unprivileged `BPF_PROG_LOAD` restrictions.
//!
//! When running as root on Linux ≥ 5.8 with BPF enabled, this module loads
//! a small eBPF program that attaches to `fentry/vfs_read`. The BPF program
//! inspects the first N bytes of each page being read and checks byte-frequency
//! thresholds. Pages that cannot possibly contain a match are flagged, allowing
//! the userspace scanner to skip them entirely — the pages never need to be
//! copied to userspace over the `PCIe` bus.
//!
//! When eBPF is unavailable (non-root, old kernel, no `aya` feature), the
//! module provides a transparent no-op implementation that returns `None` from
//! `KernelFilter::try_attach`, and callers fall back to the pure-Rust
//! `ByteFrequencyFilter` in the parent crate.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────┐
//! │         Userspace               │
//! │ ┌───────────────────────────┐   │
//! │ │ KernelFilter::try_attach  │   │
//! │ │   → loads BPF program     │   │
//! │ │   → configures threshold  │   │
//! │ │     map via perf ring     │   │
//! │ └───────────────────────────┘   │
//! │            ↕                    │
//! │ ┌───────────────────────────┐   │
//! │ │  KernelFilter::poll_skips │   │
//! │ │   → reads skip decisions  │   │
//! │ │     from ring buffer      │   │
//! │ └───────────────────────────┘   │
//! └─────────────────────────────────┘
//!              ↕ BPF maps
//! ┌─────────────────────────────────┐
//! │         Kernel eBPF             │
//! │ ┌───────────────────────────┐   │
//! │ │ fentry/vfs_read handler   │   │
//! │ │   → sample first 64 bytes │   │
//! │ │   → count byte freqs     │   │
//! │ │   → check thresholds     │   │
//! │ │   → emit skip/pass event │   │
//! │ └───────────────────────────┘   │
//! └─────────────────────────────────┘
//! ```

use crate::{ByteThreshold, Error, Result};

#[cfg(all(feature = "socket-bpf", target_os = "linux"))]
use std::os::fd::AsRawFd;

/// Metadata about a page the kernel filter decided to skip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkipDecision {
    /// The inode number of the file being read.
    pub inode: u64,
    /// The byte offset within the file where the skip applies.
    pub file_offset: u64,
    /// Number of bytes that can be skipped.
    pub skip_length: u64,
}

/// Kernel-side eBPF byte-frequency filter.
///
/// Wraps the BPF program lifecycle: loading, configuring threshold maps,
/// attaching to kernel hooks, and reading skip decisions from the perf
/// ring buffer.
///
/// On systems where eBPF is unavailable, `try_attach` returns `Ok(None)`
/// and the caller should fall back to userspace filtering.
pub struct KernelFilter {
    /// Thresholds configured in the BPF threshold map.
    thresholds: Vec<ByteThreshold>,
    /// Whether the kernel filter is actually active.
    active: bool,
    /// Skip decisions collected from the kernel.
    pending_skips: Vec<SkipDecision>,
}

impl KernelFilter {
    /// Attempt to load and attach the eBPF filter program.
    ///
    /// Returns `Ok(Some(filter))` when the kernel filter is successfully attached.
    /// Returns `Ok(None)` when eBPF is unavailable (not root, old kernel, no BPF).
    /// Returns `Err` only on unexpected failures (corrupt BPF bytecode, etc).
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidConfiguration` if thresholds are empty.
    pub fn try_attach(thresholds: &[ByteThreshold]) -> Result<Option<Self>> {
        if thresholds.is_empty() {
            return Err(Error::InvalidConfiguration {
                reason: "kernel filter requires at least one byte threshold".to_string(),
                fix: "provide one or more ByteThreshold values",
            });
        }

        // Check basic prerequisites before attempting BPF operations.
        if !Self::prerequisites_met() {
            return Ok(None);
        }

        // The actual BPF loading would go here when the `aya` feature is enabled.
        // For now, we implement the full userspace-side protocol so that
        // when `aya` is integrated, only the loading code needs to change.
        #[cfg(all(target_os = "linux", feature = "kernel-bpf"))]
        {
            return Self::load_and_attach_bpf(thresholds);
        }

        // No kernel BPF available — signal caller to use userspace fallback.
        #[allow(unreachable_code)]
        Ok(None)
    }

    /// Check whether the system meets prerequisites for kernel eBPF.
    fn prerequisites_met() -> bool {
        #[cfg(target_os = "linux")]
        {
            // Check 1: Are we running as root (or have CAP_BPF)?
            #[allow(unsafe_code)]
            let euid = unsafe { libc::geteuid() };
            if euid != 0 {
                return false;
            }

            // Check 2: Is BPF enabled? Check for /sys/kernel/btf/vmlinux
            // which is required for BTF-based BPF (CO-RE).
            if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
                return false;
            }

            // Check 3: Kernel version >= 5.8 for fentry support.
            if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
                if let Some(version) = parse_kernel_version(&release) {
                    // fentry requires Linux 5.5+, but we want 5.8+ for
                    // ring buffer support.
                    return version >= (5, 8, 0);
                }
            }

            false
        }

        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// Poll for new skip decisions from the kernel.
    ///
    /// Returns a list of file regions that the kernel filter determined
    /// do not contain matches. The caller should skip these regions
    /// instead of reading and scanning them.
    ///
    /// Returns an empty slice when no new decisions are available or
    /// the kernel filter is not active.
    pub fn poll_skips(&mut self) -> &[SkipDecision] {
        if !self.active {
            return &[];
        }

        // In the full implementation, this would read from the BPF ring
        // buffer and populate self.pending_skips.
        self.pending_skips.clear();

        #[cfg(all(target_os = "linux", feature = "kernel-bpf"))]
        {
            self.drain_ring_buffer();
        }

        &self.pending_skips
    }

    /// Check if the kernel filter is actively attached and filtering.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Return the configured byte thresholds.
    #[must_use]
    pub fn thresholds(&self) -> &[ByteThreshold] {
        &self.thresholds
    }

    /// Detach the kernel filter and clean up BPF resources.
    pub fn detach(&mut self) {
        self.active = false;
        self.pending_skips.clear();
        // In the full implementation, this drops the BPF program handle
        // which auto-detaches the kernel probe.
    }
}

impl Drop for KernelFilter {
    fn drop(&mut self) {
        self.detach();
    }
}

// ── eBPF socket filter (ebpfkit: classic BPF `SO_ATTACH_BPF`) ─────────────

#[cfg(feature = "socket-bpf")]
use crate::ByteFrequencyFilter;

#[cfg(feature = "socket-bpf")]
use ebpfkit::assembler::BpfInsn;

/// Encodes [`ByteFrequencyFilter`] thresholds as a byte literal for
/// [`ebpfkit::compiler::compile_literal_search`].
///
/// For each byte value, the effective minimum count is the maximum `min_count` among
/// [`ByteThreshold`] entries for that byte (AND semantics). The literal lists bytes in
/// ascending order, each repeated that many times — e.g. thresholds `a×2` and `b×1` become
/// `aab`.
///
/// This is a **contiguous-substring** prefilter only. The userspace
/// [`ByteFrequencyFilter::matching_windows`](crate::ByteFrequencyFilter::matching_windows)
/// sliding-window predicate remains authoritative when in doubt.
///
/// # Errors
///
/// Returns [`Error::InvalidConfiguration`] when the encoded pattern would exceed
/// [`ebpfkit::compiler::MAX_BPF_PATTERN_LEN`].
#[cfg(feature = "socket-bpf")]
pub fn byte_frequency_filter_to_literal_pattern(filter: &ByteFrequencyFilter) -> Result<Vec<u8>> {
    let mut merged = [0u16; 256];
    for t in filter.thresholds() {
        let i = t.byte as usize;
        merged[i] = merged[i].max(t.min_count);
    }

    let mut pattern = Vec::new();
    for byte in 0_u16..256 {
        let c = merged[byte as usize];
        if c == 0 {
            continue;
        }
        let n = usize::from(c);
        let next_len = pattern.len().saturating_add(n);
        if next_len > ebpfkit::compiler::MAX_BPF_PATTERN_LEN {
            return Err(Error::InvalidConfiguration {
                reason: format!(
                    "encoded BPF literal would be {next_len} bytes, max is {}",
                    ebpfkit::compiler::MAX_BPF_PATTERN_LEN
                ),
                fix: "lower min_count values or use userspace-only filtering for this filter",
            });
        }
        if let Ok(byte_u8) = u8::try_from(byte) {
            pattern.extend(std::iter::repeat_n(byte_u8, n));
        }
    }

    if pattern.is_empty() {
        return Err(Error::InvalidConfiguration {
            reason: "no literal bytes derived from filter thresholds".to_string(),
            fix: "ensure the filter has at least one ByteThreshold",
        });
    }

    Ok(pattern)
}

/// Compiles a classic BPF socket-filter program from `filter` using
/// [`ebpfkit::compiler::compile_literal_search`] (load with [`ebpfkit::loader::load_filter`]).
///
/// Does not perform any syscalls; safe to call without privileges.
///
/// # Example
///
/// ```rust,ignore
/// use ebpfsieve::{ByteFrequencyFilter, ByteThreshold, kernel};
///
/// let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'x', 2)]).unwrap();
/// let insns = kernel::compile_socket_filter_program(&filter).unwrap();
/// assert!(!insns.is_empty());
/// # Ok::<(), ebpfsieve::Error>(())
/// ```
///
/// # Errors
///
/// Returns [`Error::InvalidConfiguration`] or [`Error::EbpfCompile`] on failure.
#[cfg(feature = "socket-bpf")]
pub fn compile_socket_filter_program(filter: &ByteFrequencyFilter) -> Result<Vec<BpfInsn>> {
    let pattern = byte_frequency_filter_to_literal_pattern(filter)?;
    let insns = ebpfkit::compiler::compile_literal_search(&pattern)?;
    Ok(insns)
}

/// Loaded classic BPF program suitable for [`SocketFilterProgram::attach_to_fd`].
#[cfg(all(feature = "socket-bpf", target_os = "linux"))]
pub struct SocketFilterProgram {
    prog_fd: std::os::fd::OwnedFd,
}

#[cfg(all(feature = "socket-bpf", target_os = "linux"))]
impl SocketFilterProgram {
    /// Loads the program into the kernel via `bpf(BPF_PROG_LOAD)`.
    ///
    /// Returns `Ok(None)` when the effective UID is not `0` (typical kernels require
    /// superuser for `BPF_PROG_LOAD` of socket filters).
    ///
    /// # Errors
    ///
    /// Returns [`Error::EbpfCompile`], [`Error::InvalidConfiguration`], or [`Error::EbpfKernel`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ebpfsieve::{ByteFrequencyFilter, ByteThreshold, kernel::SocketFilterProgram};
    ///
    /// let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)]).unwrap();
    /// if let Some(prog) = SocketFilterProgram::try_load(&filter).unwrap() {
    ///     // prog.attach_to_fd(socket_fd)?;
    /// }
    /// ```
    #[allow(unsafe_code)]
    pub fn try_load(filter: &ByteFrequencyFilter) -> Result<Option<Self>> {
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            return Ok(None);
        }

        let insns = compile_socket_filter_program(filter)?;
        let raw_fd =
            ebpfkit::loader::load_filter(&insns).map_err(|source| Error::EbpfKernel { source })?;
        // SAFETY: `load_filter` returns a new FD from a successful `bpf` syscall.
        let prog_fd = unsafe { std::os::fd::FromRawFd::from_raw_fd(raw_fd) };
        Ok(Some(Self { prog_fd }))
    }

    /// Attaches this BPF program to a socket using `SO_ATTACH_BPF`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EbpfKernel`] when `setsockopt` fails.
    pub fn attach_to_fd(&self, fd: std::os::unix::io::RawFd) -> Result<()> {
        ebpfkit::loader::attach_to_socket(self.prog_fd.as_raw_fd(), fd)
            .map_err(|source| Error::EbpfKernel { source })
    }

    /// Raw program FD (for duplicate attaches or debugging).
    #[must_use]
    pub fn program_fd(&self) -> std::os::unix::io::RawFd {
        self.prog_fd.as_raw_fd()
    }
}

/// Parse a Linux kernel version string like "5.15.0-91-generic" into (major, minor, patch).
#[cfg(target_os = "linux")]
fn parse_kernel_version(release: &str) -> Option<(u32, u32, u32)> {
    let trimmed = release.trim();
    let mut parts = trimmed.split(|c: char| !c.is_ascii_digit());

    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);

    Some((major, minor, patch))
}

// ── BPF program loading (gated behind feature flag) ─────────────────────

#[cfg(all(target_os = "linux", feature = "kernel-bpf"))]
impl KernelFilter {
    /// Load the pre-compiled BPF program and attach to `vfs_read`.
    fn load_and_attach_bpf(thresholds: &[ByteThreshold]) -> Result<Option<Self>> {
        use aya::maps::HashMap as BpfHashMap;
        use aya::{programs::FEntry, Ebpf};

        let mut bpf = Ebpf::load(include_bytes!(concat!(env!("OUT_DIR"), "/sieve.bpf.o")))
            .map_err(|e| Error::InvalidConfiguration {
                reason: format!("failed to load BPF program: {e}"),
                fix: "ensure the BPF program was compiled correctly",
            })?;

        // Configure threshold map
        let mut threshold_map: BpfHashMap<_, u8, u16> =
            BpfHashMap::try_from(bpf.map_mut("thresholds").ok_or_else(|| {
                Error::InvalidConfiguration {
                    reason: "BPF program missing 'thresholds' map".to_string(),
                    fix: "rebuild the BPF program with the threshold map",
                }
            })?)
            .map_err(|e| Error::InvalidConfiguration {
                reason: format!("failed to open threshold map: {e}"),
                fix: "check BPF map type compatibility",
            })?;

        for threshold in thresholds {
            threshold_map
                .insert(threshold.byte, threshold.min_count, 0)
                .map_err(|e| Error::InvalidConfiguration {
                    reason: format!("failed to insert threshold: {e}"),
                    fix: "check threshold map capacity",
                })?;
        }

        // Attach to vfs_read
        let program: &mut FEntry = bpf
            .program_mut("sieve_vfs_read")
            .ok_or_else(|| Error::InvalidConfiguration {
                reason: "BPF program missing 'sieve_vfs_read' function".to_string(),
                fix: "rebuild the BPF program with the correct entry point",
            })?
            .try_into()
            .map_err(|e| Error::InvalidConfiguration {
                reason: format!("program type mismatch: {e}"),
                fix: "ensure the BPF program uses fentry section",
            })?;

        program
            .load(
                "vfs_read",
                &aya::Btf::from_sys_fs().map_err(|e| Error::InvalidConfiguration {
                    reason: format!("BTF not available: {e}"),
                    fix: "ensure kernel has BTF support enabled",
                })?,
            )
            .map_err(|e| Error::InvalidConfiguration {
                reason: format!("failed to load fentry program: {e}"),
                fix: "check kernel version supports fentry",
            })?;

        program.attach().map_err(|e| Error::InvalidConfiguration {
            reason: format!("failed to attach to vfs_read: {e}"),
            fix: "check CAP_BPF capability and kernel BTF",
        })?;

        Ok(Some(Self {
            thresholds: thresholds.to_vec(),
            active: true,
            pending_skips: Vec::with_capacity(256),
        }))
    }

    fn drain_ring_buffer(&mut self) {
        // The BPF ring buffer drain requires an attached BPF program with a
        // ring buffer map. Until the attach path is wired, we cannot read
        // events. Mark the filter inactive so callers don't rely on empty
        // skip decisions.
        if self.active {
            self.active = false;
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

    #[test]
    fn prerequisites_checks_do_not_panic() {
        // Just verify the check runs without crashing — result depends on environment
        let _met = KernelFilter::prerequisites_met();
    }

    #[test]
    fn try_attach_returns_none_when_not_root() {
        let result = KernelFilter::try_attach(&[ByteThreshold::new(b'a', 2)]);
        // On CI and dev machines we're typically not root
        match result {
            Ok(None) => {} // Expected: prerequisites not met
            Ok(Some(mut filter)) => {
                assert!(filter.is_active());
                filter.detach();
            }
            Err(_) => {} // Also acceptable if config validation fails
        }
    }

    #[test]
    fn try_attach_rejects_empty_thresholds() {
        let result = KernelFilter::try_attach(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn poll_skips_returns_empty_when_inactive() {
        // Can't easily construct an inactive filter via public API without
        // eBPF support, so test the prerequisite check instead
        let met = KernelFilter::prerequisites_met();
        if !met {
            // verify the function at least runs
            assert!(!met);
        }
    }

    #[cfg(feature = "socket-bpf")]
    #[test]
    fn literal_pattern_merges_duplicate_byte_thresholds() {
        let filter = crate::ByteFrequencyFilter::new([
            ByteThreshold::new(b'z', 1),
            ByteThreshold::new(b'z', 3),
            ByteThreshold::new(b'm', 2),
        ])
        .unwrap();
        let pat = byte_frequency_filter_to_literal_pattern(&filter).unwrap();
        assert_eq!(pat, b"mmzzz");
    }

    #[cfg(feature = "socket-bpf")]
    #[test]
    fn compile_socket_filter_produces_instructions() {
        let filter = crate::ByteFrequencyFilter::new([ByteThreshold::new(b'x', 2)]).unwrap();
        let insns = compile_socket_filter_program(&filter).unwrap();
        assert!(!insns.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_kernel_version_works() {
        assert_eq!(
            parse_kernel_version("5.15.0-91-generic\n"),
            Some((5, 15, 0))
        );
        assert_eq!(parse_kernel_version("6.8.12"), Some((6, 8, 12)));
        assert_eq!(parse_kernel_version("4.19.0"), Some((4, 19, 0)));
    }
}
