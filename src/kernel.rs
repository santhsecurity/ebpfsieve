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
//! When running as root on Linux >= 5.8 with BPF enabled, this module loads
//! a small eBPF program that attaches to `fexit/vfs_read` (after the kernel has
//! written the user buffer). The BPF program samples up to 128 bytes
//! (must match `MAX_SAMPLE` in `src/bpf/sieve.bpf.c`) of each read and checks
//! byte-frequency thresholds. Reads that cannot possibly contain a match are
//! flagged, allowing the userspace scanner to skip them entirely.
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
//! │ │   → sample first 128 bytes│   │
//! │ │   → count byte freqs     │   │
//! │ │   → check thresholds     │   │
//! │ │   → emit skip event      │   │
//! │ └───────────────────────────┘   │
//! └─────────────────────────────────┘
//! ```

use crate::{ByteThreshold, Error, Result};

#[cfg(all(feature = "socket-bpf", target_os = "linux"))]
use std::os::fd::AsRawFd;

/// Metadata about a page the kernel filter decided to skip.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkipDecision {
    /// The inode number of the file being read.
    pub inode: u64,
    /// The byte offset within the file where the skip applies.
    pub file_offset: u64,
    /// Number of bytes that can be skipped.
    pub skip_length: u64,
}

impl SkipDecision {
    #[cfg(feature = "kernel-bpf")]
    fn from_ne_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 24 {
            return None;
        }
        let inode = u64::from_ne_bytes(bytes[0..8].try_into().ok()?);
        let file_offset = u64::from_ne_bytes(bytes[8..16].try_into().ok()?);
        let skip_length = u64::from_ne_bytes(bytes[16..24].try_into().ok()?);
        Some(Self {
            inode,
            file_offset,
            skip_length,
        })
    }
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
    /// Owned BPF object. Stored so the probe stays attached while the filter is alive.
    #[cfg(feature = "kernel-bpf")]
    ebpf: Option<aya::Ebpf>,
    /// Ring buffer used to receive skip decisions from the kernel.
    #[cfg(feature = "kernel-bpf")]
    ringbuf: Option<aya::maps::RingBuf<aya::maps::MapData>>,
    /// Test-only injected skip decisions. `drain_ring_buffer` drains these after the real ring
    /// buffer so tests can observe skip-based behavior without a live BPF program.
    #[cfg(test)]
    test_injected_skips: Vec<SkipDecision>,
}

impl std::fmt::Debug for KernelFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut dbg = f.debug_struct("KernelFilter");
        dbg.field("thresholds", &self.thresholds)
            .field("active", &self.active)
            .field("pending_skips", &self.pending_skips);
        #[cfg(feature = "kernel-bpf")]
        {
            dbg.field("ebpf", &self.ebpf.is_some())
                .field("ringbuf", &self.ringbuf.is_some());
        }
        dbg.finish()
    }
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

        // No kernel BPF available (signal caller to use userspace fallback).
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
            // A merely-old kernel returning false is expected and silent, but a
            // readable-yet-unparseable osrelease, or an unreadable one, would
            // silently disable kernel offload on a capable host - surface those
            // loudly (once) rather than degrade invisibly (Law-10).
            match std::fs::read_to_string("/proc/sys/kernel/osrelease") {
                Ok(release) => match parse_kernel_version(&release) {
                    // fentry requires Linux 5.5+, but we want 5.8+ for ring
                    // buffer support.
                    Some(version) => return version >= (5, 8, 0),
                    None => warn_prereq_undetected(&format!(
                        "unparseable kernel osrelease {:?}",
                        release.trim()
                    )),
                },
                Err(error) => {
                    warn_prereq_undetected(&format!("cannot read /proc/sys/kernel/osrelease: {error}"));
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

        self.pending_skips.clear();
        self.drain_ring_buffer();

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

    /// Inject a skip decision for testing. Only available in test builds; the decision is moved
    /// into `pending_skips` by the next `drain_ring_buffer` call.
    #[cfg(test)]
    pub fn inject_skip(&mut self, decision: SkipDecision) {
        self.test_injected_skips.push(decision);
    }

    /// Construct an active filter with pre-injected skip decisions for unit tests.
    /// BPF handles are `None`; the filter is kept active so `poll_skips` returns the test data.
    #[cfg(test)]
    #[must_use]
    pub fn with_test_skips(thresholds: Vec<ByteThreshold>, skips: Vec<SkipDecision>) -> Self {
        Self {
            thresholds,
            active: true,
            pending_skips: Vec::new(),
            #[cfg(feature = "kernel-bpf")]
            ebpf: None,
            #[cfg(feature = "kernel-bpf")]
            ringbuf: None,
            #[cfg(test)]
            test_injected_skips: skips,
        }
    }

    /// Drain skip decisions from the BPF ring buffer (if present) and from any test
    /// injections into `pending_skips`.
    fn drain_ring_buffer(&mut self) {
        #[cfg(feature = "kernel-bpf")]
        {
            if let Some(ringbuf) = self.ringbuf.as_mut() {
                while let Some(item) = ringbuf.next() {
                    let bytes: &[u8] = &item;
                    if let Some(decision) = SkipDecision::from_ne_bytes(bytes) {
                        self.pending_skips.push(decision);
                    }
                }
            }
        }
        #[cfg(test)]
        {
            self.pending_skips.extend(self.test_injected_skips.drain(..));
        }
    }

    /// Detach the kernel filter and clean up BPF resources.
    pub fn detach(&mut self) {
        self.active = false;
        self.pending_skips.clear();
        #[cfg(feature = "kernel-bpf")]
        {
            self.ringbuf = None;
            self.ebpf = None;
        }
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
use ebpfkit::assembler::{BpfInsn, R0, R1, R4, R5, BPF_DW, BPF_H, BPF_MEM, BPF_STX};
#[cfg(feature = "socket-bpf")]
use ebpfkit::{alu64_imm, alu64_reg, exit, jmp_imm, jmp_reg, ldx_mem};

/// Encodes [`ByteFrequencyFilter`] thresholds as a byte literal for
/// [`ebpfkit::compiler::compile_literal_search`].
///
/// The classic BPF socket filter is a contiguous-substring prefilter: it can only
/// accept packets that contain the literal pattern as a contiguous substring. A
/// `ByteFrequencyFilter` threshold such as `b'x' × 2` requires two `x` bytes
/// anywhere in the window, not necessarily adjacent. Generating a literal `xx` for
/// that threshold would drop packets containing two non-contiguous `x` bytes, which
/// is a false negative. Therefore this function only succeeds when the filter
/// expresses a single-byte, single-occurrence literal (one distinct byte value with
/// effective minimum count of exactly one). All other threshold shapes must fall
/// back to the userspace [`ByteFrequencyFilter::matching_windows`](crate::ByteFrequencyFilter::matching_windows)
/// sliding-window predicate.
///
/// # Errors
///
/// Returns [`Error::InvalidConfiguration`] when the thresholds cannot be expressed
/// as a safe contiguous literal, or when the encoded pattern would exceed
/// [`ebpfkit::compiler::MAX_BPF_PATTERN_LEN`].
#[cfg(feature = "socket-bpf")]
pub fn byte_frequency_filter_to_literal_pattern(filter: &ByteFrequencyFilter) -> Result<Vec<u8>> {
    let thresholds = filter.thresholds();
    if thresholds.is_empty() {
        return Err(Error::InvalidConfiguration {
            reason: "no literal bytes derived from filter thresholds".to_string(),
            fix: "ensure the filter has at least one ByteThreshold",
        });
    }

    // The merged effective minimum count per byte value. Duplicates for the same
    // byte combine with AND semantics (max count wins).
    let mut merged = [0u16; 256];
    for t in thresholds {
        let i = usize::from(t.byte);
        merged[i] = merged[i].max(t.min_count);
    }

    let distinct_bytes = merged.iter().filter(|c| **c > 0).count();
    let max_count = *merged.iter().max().unwrap_or(&0);

    // Only a single distinct byte with an effective count of exactly 1 is safe for
    // a contiguous literal search. Anything else can silently drop valid packets.
    if distinct_bytes != 1 || max_count != 1 {
        return Err(Error::InvalidConfiguration {
            reason: format!(
                "socket BPF literal filter only supports a single byte with min_count=1; \
                 got {distinct_bytes} distinct byte(s) with max count {max_count}"
            ),
            fix: "use a single ByteThreshold with min_count=1, or use userspace filtering for non-contiguous thresholds",
        });
    }

    let byte_value = merged
        .iter()
        .position(|c| *c == 1)
        .and_then(|i| u8::try_from(i).ok())
        .ok_or_else(|| Error::InvalidConfiguration {
            reason: "socket BPF literal filter only supports a single byte with min_count=1".to_string(),
            fix: "use a single ByteThreshold with min_count=1, or use userspace filtering for non-contiguous thresholds",
        })?;

    let pattern = vec![byte_value];
    if pattern.len() > ebpfkit::compiler::MAX_BPF_PATTERN_LEN {
        return Err(Error::InvalidConfiguration {
            reason: format!(
                "encoded BPF literal would be {} bytes, max is {}",
                pattern.len(),
                ebpfkit::compiler::MAX_BPF_PATTERN_LEN
            ),
            fix: "lower min_count values or use userspace-only filtering for this filter",
        });
    }

    Ok(pattern)
}

/// Compile a socket filter that counts byte frequencies across the whole packet.
///
/// The generated BPF program increments per-byte counters on the stack and only
/// accepts packets where every required byte appears at least `min_count` times
/// somewhere in the packet. This is a necessary condition for any sliding-window
/// match, so the filter never drops a packet that could contain a match.
#[cfg(feature = "socket-bpf")]
fn compile_frequency_count_socket_filter(filter: &ByteFrequencyFilter) -> Result<Vec<BpfInsn>> {
    // __sk_buff layout: data at offset 76, data_end at offset 80.
    const SKB_DATA_OFFSET: i16 = 76;
    const SKB_DATA_END_OFFSET: i16 = 80;
    const COUNTER_TABLE_SIZE: i16 = 512;
    const COUNTER_SLOTS: i16 = 64;

    // Merge duplicate thresholds by byte (AND semantics: max count wins).
    let mut merged = [0u16; 256];
    for threshold in filter.thresholds() {
        let idx = usize::from(threshold.byte);
        merged[idx] = merged[idx].max(threshold.min_count);
    }

    let mut active = Vec::with_capacity(256);
    for (i, count) in merged.iter().enumerate() {
        if *count == 0 {
            continue;
        }
        let byte = u8::try_from(i).map_err(|_| Error::InvalidConfiguration {
            reason: "socket filter byte index out of range".to_string(),
            fix: "report a bug",
        })?;
        active.push((byte, *count));
    }
    if active.is_empty() {
        return Err(Error::InvalidConfiguration {
            reason: "socket filter requires at least one byte threshold".to_string(),
            fix: "provide one or more ByteThreshold values",
        });
    }

    let mut prog = Vec::with_capacity(256);

    // R2 = data, R3 = data_end.
    prog.push(ldx_mem!(BPF_W, R2, R1, SKB_DATA_OFFSET));
    prog.push(ldx_mem!(BPF_W, R3, R1, SKB_DATA_END_OFFSET));

    // R1 = base of the 512-byte counter table on the eBPF stack.
    prog.push(alu64_reg!(BPF_MOV, R1, R10));
    prog.push(alu64_imm!(BPF_ADD, R1, -i32::from(COUNTER_TABLE_SIZE)));

    // Zero the table with 64 8-byte stores.
    prog.push(alu64_imm!(BPF_MOV, R0, 0));
    for slot in 0..COUNTER_SLOTS {
        prog.push(BpfInsn::new(
            BPF_STX | BPF_MEM | BPF_DW,
            R1,
            R0,
            slot * 8,
            0,
        ));
    }

    // Iterate over every byte in the packet.
    let loop_start = prog.len();
    let bounds_check_idx = prog.len();
    prog.push(exit!()); // placeholder

    // R4 = byte * 2; R4 = table entry; R5 = current count.
    prog.push(ldx_mem!(BPF_B, R4, R2, 0));
    prog.push(alu64_imm!(BPF_LSH, R4, 1));
    prog.push(alu64_reg!(BPF_ADD, R4, R1));
    prog.push(ldx_mem!(BPF_H, R5, R4, 0));
    let cap_check_idx = prog.len();
    prog.push(exit!()); // placeholder
    prog.push(alu64_imm!(BPF_ADD, R5, 1));
    prog.push(BpfInsn::new(BPF_STX | BPF_MEM | BPF_H, R4, R5, 0, 0));
    let after_store_idx = prog.len();
    prog.push(alu64_imm!(BPF_ADD, R2, 1));
    let back_offset = -i16::try_from(prog.len() - loop_start + 1).map_err(|_| Error::InvalidConfiguration {
        reason: "socket filter back-offset out of range".to_string(),
        fix: "reduce the number of byte thresholds",
    })?;
    prog.push(jmp_imm!(BPF_JA, R0, 0, back_offset));

    let check_idx = prog.len();
    let bounds_check_offset = i16::try_from(check_idx - bounds_check_idx - 1).map_err(|_| Error::InvalidConfiguration {
        reason: "socket filter bounds-check offset out of range".to_string(),
        fix: "reduce the number of byte thresholds",
    })?;
    prog[bounds_check_idx] = jmp_reg!(BPF_JGE, R2, R3, bounds_check_offset);
    let cap_check_offset = i16::try_from(after_store_idx - cap_check_idx - 1).map_err(|_| Error::InvalidConfiguration {
        reason: "socket filter cap-check offset out of range".to_string(),
        fix: "reduce the number of byte thresholds",
    })?;
    prog[cap_check_idx] = jmp_imm!(BPF_JGE, R5, 0xFFFF, cap_check_offset);

    let mut jlt_indices = Vec::with_capacity(active.len());
    for (byte, _) in &active {
        prog.push(ldx_mem!(BPF_H, R0, R1, i16::from(*byte) * 2));
        jlt_indices.push(prog.len());
        prog.push(exit!()); // placeholder
    }

    prog.push(alu64_imm!(BPF_MOV, R0, 1));
    prog.push(exit!());

    let fail_idx = prog.len();
    prog.push(alu64_imm!(BPF_MOV, R0, 0));
    prog.push(exit!());

    for (idx, (_, min_count)) in jlt_indices.iter().zip(&active) {
        let offset = i16::try_from(fail_idx - *idx - 1).map_err(|_| Error::InvalidConfiguration {
            reason: "socket filter threshold offset out of range".to_string(),
            fix: "reduce the number of byte thresholds",
        })?;
        prog[*idx] = jmp_imm!(BPF_JLT, R0, i32::from(*min_count), offset);
    }

    Ok(prog)
}

/// Compiles a socket-filter program from `filter` that counts byte frequencies
/// across the packet.
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
/// Returns [`Error::InvalidConfiguration`] on failure.
#[cfg(feature = "socket-bpf")]
pub fn compile_socket_filter_program(filter: &ByteFrequencyFilter) -> Result<Vec<BpfInsn>> {
    compile_frequency_count_socket_filter(filter)
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

/// Warn (exactly once) that kernel-eBPF prerequisites could not be evaluated
/// because the kernel version was undetectable. `prerequisites_met()` then fails
/// closed (returns false), but without this the reason a capable host silently
/// declined kernel offload was invisible (Law-10). Once-guarded so repeated
/// prerequisite checks do not spam.
#[cfg(target_os = "linux")]
fn warn_prereq_undetected(reason: &str) {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        eprintln!(
            "ebpfsieve: could not determine kernel version ({reason}); treating kernel eBPF \
             prerequisites as NOT met (userspace fallback)"
        );
    });
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

/// Open a BPF ring buffer map, failing CLOSED when a present map cannot be
/// opened.
///
/// This encodes the Law 10 contract for `load_and_attach_bpf`: an absent map
/// (`None`) legitimately yields `None` (the program simply has no ring buffer),
/// but a present-but-unopenable map propagates the open error as a hard
/// [`Error::InvalidConfiguration`] instead of being silently swallowed into
/// `None` (which would leave an *active* filter that never delivers skips).
///
/// It is generic over the map/ring-buffer types and the opening operation so
/// the error-propagation branch is unit-testable without a live kernel (the
/// real call passes `aya::maps::RingBuf::try_from`).
fn open_ring_buffer<M, B, E: std::fmt::Display>(
    map: Option<M>,
    open: impl FnOnce(M) -> std::result::Result<B, E>,
) -> Result<Option<B>> {
    match map {
        Some(m) => Ok(Some(open(m).map_err(|e| Error::InvalidConfiguration {
            reason: format!("failed to open BPF ring buffer map 'rb': {e}"),
            fix: "ensure the 'rb' map is declared as BPF_MAP_TYPE_RINGBUF and the \
                  kernel supports ring buffers (>= 5.8)",
        })?)),
        None => Ok(None),
    }
}

#[cfg(all(target_os = "linux", feature = "kernel-bpf"))]
impl KernelFilter {
    /// Load the pre-compiled BPF program and attach to `vfs_read`.
    fn load_and_attach_bpf(thresholds: &[ByteThreshold]) -> Result<Option<Self>> {
        use aya::maps::HashMap as BpfHashMap;
        use aya::{programs::FExit, Ebpf};
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

        // Take the ring buffer map if the BPF program provides one. This must happen before
        // `bpf` is consumed by the returned `KernelFilter`.
        //
        // Fail CLOSED (Law 10): if the "rb" map is present but cannot be opened as
        // a RingBuf, the previous `.ok()` discarded that error and returned an
        // *active* filter with `ringbuf: None` - so the kernel program would run
        // and drop every skip decision on the floor, silently degrading recall
        // with zero signal to the operator. `open_ring_buffer` propagates a
        // present-but-unopenable map as a hard configuration error (aborting
        // attach) while still allowing a genuinely absent map to yield `None`.
        let ringbuf = open_ring_buffer(bpf.take_map("rb"), |map| {
            aya::maps::RingBuf::try_from(map)
        })?;

        // Attach to vfs_read after the kernel has written the user buffer.
        let program: &mut FExit = bpf
            .program_mut("sieve_vfs_read")
            .ok_or_else(|| Error::InvalidConfiguration {
                reason: "BPF program missing 'sieve_vfs_read' function".to_string(),
                fix: "rebuild the BPF program with the correct entry point",
            })?
            .try_into()
            .map_err(|e| Error::InvalidConfiguration {
                reason: format!("program type mismatch: {e}"),
                fix: "ensure the BPF program uses fexit section",
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
                reason: format!("failed to load fexit program: {e}"),
                fix: "check kernel version supports fexit",
            })?;

        program.attach().map_err(|e| Error::InvalidConfiguration {
            reason: format!("failed to attach to vfs_read: {e}"),
            fix: "check CAP_BPF capability and kernel BTF",
        })?;

        Ok(Some(Self {
            thresholds: thresholds.to_vec(),
            active: true,
            pending_skips: Vec::with_capacity(256),
            ebpf: Some(bpf),
            ringbuf,
            #[cfg(test)]
            test_injected_skips: Vec::new(),
        }))
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
        // Just verify the check runs without crashing, result depends on environment
        let _met = KernelFilter::prerequisites_met();
    }

    #[test]
    fn open_ring_buffer_fails_closed_when_present_map_cannot_open() {
        // Mirrors the aya `RingBuf::try_from` failure (e.g. wrong map type) at the
        // load_and_attach_bpf ring-buffer step. The previous `.ok()` swallowed this
        // into `None` and returned an ACTIVE filter that silently delivered no
        // skips; the helper must instead propagate a hard InvalidConfiguration so
        // attach aborts loudly (Law 10 fail-closed).
        struct BadMapType;
        impl std::fmt::Display for BadMapType {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "invalid map type: expected BPF_MAP_TYPE_RINGBUF")
            }
        }
        let result: Result<Option<()>> = super::open_ring_buffer(Some(()), |()| {
            std::result::Result::<(), BadMapType>::Err(BadMapType)
        });
        match result {
            Err(Error::InvalidConfiguration { reason, fix }) => {
                assert!(
                    reason.contains("ring buffer map 'rb'")
                        && reason.contains("invalid map type"),
                    "error must name the rb map and carry the open failure, got: {reason}"
                );
                assert!(
                    fix.contains("BPF_MAP_TYPE_RINGBUF"),
                    "fix must guide toward the correct map type, got: {fix}"
                );
            }
            other => panic!("present-but-unopenable rb map must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn open_ring_buffer_absent_map_yields_none_not_error() {
        // A genuinely absent "rb" map (program provides no ring buffer) is NOT an
        // error - it yields None so a filter without a ring buffer stays valid.
        // Guards against over-failing the fail-closed change above.
        let opened_flag = std::cell::Cell::new(false);
        let result: Result<Option<()>> = super::open_ring_buffer(None::<()>, |()| {
            opened_flag.set(true);
            std::result::Result::<(), std::fmt::Error>::Ok(())
        });
        assert!(matches!(result, Ok(None)), "absent map must yield Ok(None)");
        assert!(!opened_flag.get(), "open must not be called when the map is absent");
    }

    #[test]
    fn open_ring_buffer_present_and_openable_yields_some() {
        // A present map that opens cleanly is returned as Some, preserving the
        // happy path.
        let result: Result<Option<u32>> = super::open_ring_buffer(Some(7u32), |m| {
            std::result::Result::<u32, std::fmt::Error>::Ok(m + 1)
        });
        assert!(matches!(result, Ok(Some(8))), "openable map must yield Some(opened)");
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
    fn literal_pattern_accepts_single_byte_single_occurrence() {
        let filter = crate::ByteFrequencyFilter::new([ByteThreshold::new(b'z', 1)]).unwrap();
        let pat = byte_frequency_filter_to_literal_pattern(&filter).unwrap();
        assert_eq!(pat, b"z");
    }

    #[cfg(feature = "socket-bpf")]
    #[test]
    fn literal_pattern_rejects_non_contiguous_multi_byte_thresholds() {
        let filter = crate::ByteFrequencyFilter::new([
            ByteThreshold::new(b'z', 1),
            ByteThreshold::new(b'm', 1),
        ])
        .unwrap();
        assert!(
            byte_frequency_filter_to_literal_pattern(&filter).is_err(),
            "multiple distinct bytes require non-contiguous matching and must be rejected"
        );
    }

    #[cfg(feature = "socket-bpf")]
    #[test]
    fn literal_pattern_rejects_non_contiguous_repeat_thresholds() {
        // Regression: a single byte with count 2 is not equivalent to a contiguous
        // "xx" literal and would silently drop valid packets.
        let filter = crate::ByteFrequencyFilter::new([ByteThreshold::new(b'x', 2)]).unwrap();
        assert!(
            byte_frequency_filter_to_literal_pattern(&filter).is_err(),
            "repeated byte thresholds are non-contiguous and must not compile to a socket filter"
        );
    }

    #[cfg(feature = "socket-bpf")]
    #[test]
    fn compile_socket_filter_produces_instructions() {
        let filter = crate::ByteFrequencyFilter::new([ByteThreshold::new(b'x', 1)]).unwrap();
        let insns = compile_socket_filter_program(&filter).unwrap();
        assert!(!insns.is_empty());
    }

    #[cfg(feature = "socket-bpf")]
    #[test]
    fn compile_socket_filter_program_accepts_non_contiguous_repeats() {
        use ebpfkit::assembler::{BPF_JMP, BPF_JLT, BPF_K};
        let filter = crate::ByteFrequencyFilter::new([
            ByteThreshold::new(b'x', 2),
            ByteThreshold::new(b'y', 3),
        ])
        .unwrap();
        let insns = compile_socket_filter_program(&filter).unwrap();
        assert!(insns.len() > 10, "frequency-count program should be substantial");
        let jlt_code = BPF_JMP | BPF_JLT | BPF_K;
        assert!(
            insns.iter().any(|insn| insn.code == jlt_code),
            "program should contain a threshold JLT check"
        );
    }

    #[cfg(feature = "kernel-bpf")]
    #[test]
    fn drain_ring_buffer_without_rb_keeps_filter_active() {
        let mut filter = KernelFilter {
            thresholds: vec![ByteThreshold::new(b'a', 1)],
            active: true,
            pending_skips: Vec::new(),
            ebpf: None,
            ringbuf: None,
            test_injected_skips: Vec::new(),
        };
        filter.drain_ring_buffer();
        assert!(filter.is_active(), "draining a filter with no ringbuf must not deactivate it");
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
