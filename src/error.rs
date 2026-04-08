//! Error types for ebpfsieve.

/// Errors returned by `ebpfsieve`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The filter configuration is invalid.
    #[error("invalid filter configuration: {reason}. Fix: {fix}")]
    InvalidConfiguration {
        /// Human-readable failure reason.
        reason: String,
        /// Actionable repair guidance.
        fix: &'static str,
    },
    /// Reading from the attached source failed.
    #[error("read failed: {source}. Fix: verify the reader remains open and readable")]
    ReadFailed {
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// JIT compilation of the socket BPF program failed.
    #[cfg(feature = "socket-bpf")]
    #[error(transparent)]
    EbpfCompile(#[from] ebpfkit::compiler::CompileError),
    /// A BPF syscall (`prog_load`, `setsockopt`) failed.
    #[error("eBPF kernel operation failed: {source}. Fix: run as root on Linux with BPF enabled; use a valid open socket FD for SO_ATTACH_BPF")]
    EbpfKernel {
        /// OS error from `bpf()` or `setsockopt`.
        #[source]
        source: std::io::Error,
    },
    /// Kernel socket filter is unavailable (non-Linux or not root).
    #[error("eBPF socket filter unavailable: {reason}. Fix: {fix}")]
    EbpfUnavailable {
        /// Why loading was skipped or rejected.
        reason: &'static str,
        /// How to enable this path.
        fix: &'static str,
    },
}

/// Crate-wide result type.
pub type Result<T> = std::result::Result<T, Error>;
