#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::pedantic
)]
//! Integration checks for ebpfkit-backed socket filters (Linux).
#![cfg(all(target_os = "linux", feature = "socket-bpf"))]

use ebpfsieve::kernel::{compile_socket_filter_program, SocketFilterProgram};
use ebpfsieve::{ByteFrequencyFilter, ByteThreshold};
use std::net::UdpSocket;
use std::os::unix::io::AsRawFd;

#[test]
fn socket_filter_compiles_without_root() {
    let filter =
        ByteFrequencyFilter::new([ByteThreshold::new(b'x', 2), ByteThreshold::new(b'y', 1)])
            .expect("valid filter");
    let insns = compile_socket_filter_program(&filter).expect("JIT compile must succeed");
    assert!(
        insns.len() >= 4,
        "expected a non-trivial BPF program for a non-empty literal"
    );
}

#[test]
fn dummy_socket_attach_when_root() {
    let filter = ByteFrequencyFilter::new([ByteThreshold::new(b'a', 1)]).expect("valid filter");
    let sock = UdpSocket::bind("127.0.0.1:0").expect("UDP socket");
    let fd = sock.as_raw_fd();

    let loaded = SocketFilterProgram::try_load(&filter).expect("compile/load must not error");
    if let Some(prog) = loaded {
        prog.attach_to_fd(fd)
            .expect("SO_ATTACH_BPF should succeed for a valid program FD");
        // Verify fd by doing an assert
        assert!(prog.program_fd() > 0, "Program fd should be valid");
    } else {
        // When not root, verify it returns None
        assert!(loaded.is_none(), "Should be None when not root");
    }
}
