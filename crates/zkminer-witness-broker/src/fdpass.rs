//! Frames with an attached file descriptor (`SCM_RIGHTS`), and sealed memfds (plan §10.1).
//!
//! The convention (also in `zkminer_witness::ipc`): a frame that carries an fd is written with one
//! `sendmsg` whose ancillary data holds exactly that one fd, attached to the frame's first byte; if
//! the kernel takes only part of the frame, the rest follows without ancillary data. A reader takes
//! fds only while it reads the 5-byte header, never asks for more bytes than the frame it is reading
//! has left (so one `recvmsg` never spans two frames), and refuses — closing every fd it received —
//! a frame with more than one fd or with an fd attached past its header. Whether a given message
//! must carry one is the caller's check. Every received fd is close-on-exec.
//!
//! Both halves are here, blocking ([`send_with_fd`], [`recv_with_fd`]) and async
//! ([`send_with_fd_async`], [`recv_with_fd_async`]); the miner and the broker use the same code.

use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;

use tokio::io::Interest;
use zkminer_witness::ipc::{FrameError, FRAME_HEADER_BYTES};

/// The seals on every artifact memfd: no further seals, no size change, no writes.
pub const ARTIFACT_SEALS: libc::c_int = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;

/// One received frame and the fd attached to its header, if any.
#[derive(Debug)]
pub struct FdFrame {
    pub kind: u8,
    pub payload: Vec<u8>,
    pub fd: Option<OwnedFd>,
}

fn frame_bytes(kind: u8, payload: &[u8]) -> io::Result<Vec<u8>> {
    let len = u32::try_from(payload.len()).map_err(|_| io::Error::other("frame too large"))?;
    let mut buf = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    buf.push(kind);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(payload);
    Ok(buf)
}

/// Control-message space for the fds a reader accepts before it calls the frame malformed: room
/// for several, so extras are received (and closed) rather than truncated.
const RECV_CMSG_WORDS: usize = 16;

/// One `sendmsg` of `data`, with `fd` as `SCM_RIGHTS` ancillary data if given. `MSG_NOSIGNAL`: a
/// closed peer is `EPIPE`, never `SIGPIPE`.
pub(crate) fn sendmsg_once(sock: RawFd, data: &[u8], fd: Option<RawFd>) -> io::Result<usize> {
    let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut libc::c_void, iov_len: data.len() };
    // u64 words keep the control buffer aligned for cmsghdr.
    let mut cbuf = [0u64; 4];
    // SAFETY: an all-zero msghdr is a valid empty message.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if let Some(fd) = fd {
        // SAFETY: CMSG_* compute sizes and walk `cbuf`, which is large enough for one int payload;
        // the header and data writes stay inside it.
        unsafe {
            let space = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as libc::c_uint) as usize;
            debug_assert!(space <= std::mem::size_of_val(&cbuf));
            msg.msg_control = cbuf.as_mut_ptr().cast();
            msg.msg_controllen = space as _;
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as libc::c_uint) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd);
        }
    }
    // SAFETY: msg points at live buffers for the duration of the call.
    let n = unsafe { libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// One `recvmsg` into `buf`; every `SCM_RIGHTS` fd that arrives is pushed to `fds` (owned, so
/// closed if the caller drops it). Truncated ancillary data is an error.
pub(crate) fn recvmsg_once(sock: RawFd, buf: &mut [u8], fds: &mut Vec<OwnedFd>) -> io::Result<usize> {
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
    let mut cbuf = [0u64; RECV_CMSG_WORDS];
    // SAFETY: an all-zero msghdr is a valid empty message.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&cbuf) as _;
    // SAFETY: msg points at live buffers for the duration of the call.
    let n = unsafe { libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel filled `cbuf` with well-formed cmsghdrs up to msg_controllen; CMSG_NXTHDR
    // bounds the walk. Each SCM_RIGHTS int is a new fd this process now owns.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(cmsg).cast::<RawFd>();
                let bytes = (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                for i in 0..bytes / std::mem::size_of::<RawFd>() {
                    fds.push(OwnedFd::from_raw_fd(std::ptr::read_unaligned(data.add(i))));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "ancillary data truncated"));
    }
    Ok(n as usize)
}

pub(crate) fn retry_eintr<T>(mut f: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    loop {
        match f() {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            r => return r,
        }
    }
}

/// Writes one frame `kind ‖ len ‖ payload` on a blocking socket, with `fd` attached to its first
/// byte.
pub fn send_with_fd(sock: &UnixStream, kind: u8, payload: &[u8], fd: Option<BorrowedFd<'_>>) -> io::Result<()> {
    let buf = frame_bytes(kind, payload)?;
    let raw = sock.as_raw_fd();
    let mut off = retry_eintr(|| sendmsg_once(raw, &buf, fd.map(|f| f.as_raw_fd())))?;
    while off < buf.len() {
        off += retry_eintr(|| sendmsg_once(raw, &buf[off..], None))?;
    }
    Ok(())
}

/// Reads one frame from a blocking socket. `Ok(None)` is a clean close at a frame boundary.
pub fn recv_with_fd(sock: &UnixStream, max: u32) -> Result<Option<FdFrame>, FrameError> {
    let raw = sock.as_raw_fd();
    let mut header = [0u8; FRAME_HEADER_BYTES];
    let mut fds = Vec::new();
    let mut got = 0;
    while got < header.len() {
        let n = retry_eintr(|| recvmsg_once(raw, &mut header[got..], &mut fds))?;
        if n == 0 {
            return eof(got);
        }
        got += n;
    }
    let len = check_len(&header, max)?;
    let mut payload = vec![0u8; len];
    let mut late = Vec::new();
    got = 0;
    while got < len {
        let n = retry_eintr(|| recvmsg_once(raw, &mut payload[got..], &mut late))?;
        if n == 0 {
            return eof(1);
        }
        got += n;
    }
    finish(header[0], payload, fds, late)
}

/// Async [`send_with_fd`] on a tokio socket.
pub async fn send_with_fd_async(
    sock: &tokio::net::UnixStream,
    kind: u8,
    payload: &[u8],
    fd: Option<BorrowedFd<'_>>,
) -> io::Result<()> {
    let buf = frame_bytes(kind, payload)?;
    let raw = sock.as_raw_fd();
    let fd = fd.map(|f| f.as_raw_fd());
    let mut off = sock.async_io(Interest::WRITABLE, || retry_eintr(|| sendmsg_once(raw, &buf, fd))).await?;
    while off < buf.len() {
        off += sock.async_io(Interest::WRITABLE, || retry_eintr(|| sendmsg_once(raw, &buf[off..], None))).await?;
    }
    Ok(())
}

/// Async [`recv_with_fd`] on a tokio socket.
pub async fn recv_with_fd_async(sock: &tokio::net::UnixStream, max: u32) -> Result<Option<FdFrame>, FrameError> {
    let raw = sock.as_raw_fd();
    let mut header = [0u8; FRAME_HEADER_BYTES];
    let mut fds = Vec::new();
    let mut got = 0;
    while got < header.len() {
        let n = sock
            .async_io(Interest::READABLE, || retry_eintr(|| recvmsg_once(raw, &mut header[got..], &mut fds)))
            .await?;
        if n == 0 {
            return eof(got);
        }
        got += n;
    }
    let len = check_len(&header, max)?;
    let mut payload = vec![0u8; len];
    let mut late = Vec::new();
    got = 0;
    while got < len {
        let n = sock
            .async_io(Interest::READABLE, || retry_eintr(|| recvmsg_once(raw, &mut payload[got..], &mut late)))
            .await?;
        if n == 0 {
            return eof(1);
        }
        got += n;
    }
    finish(header[0], payload, fds, late)
}

fn eof(got: usize) -> Result<Option<FdFrame>, FrameError> {
    if got == 0 {
        Ok(None)
    } else {
        Err(FrameError::Io(io::ErrorKind::UnexpectedEof.into()))
    }
}

fn check_len(header: &[u8; FRAME_HEADER_BYTES], max: u32) -> Result<usize, FrameError> {
    let len = u32::from_be_bytes(header[1..].try_into().expect("4 bytes"));
    if len > max {
        return Err(FrameError::TooLarge { len, max });
    }
    Ok(len as usize)
}

fn finish(kind: u8, payload: Vec<u8>, mut fds: Vec<OwnedFd>, late: Vec<OwnedFd>) -> Result<Option<FdFrame>, FrameError> {
    if !late.is_empty() || fds.len() > 1 {
        return Err(FrameError::Malformed);
    }
    Ok(Some(FdFrame { kind, payload, fd: fds.pop() }))
}

/// A new memfd that can be sealed (`MFD_ALLOW_SEALING | MFD_CLOEXEC`).
pub fn memfd(name: &CStr) -> io::Result<File> {
    // SAFETY: a valid NUL-terminated name; the returned fd is new and owned here.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING | libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh descriptor nobody else owns.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}

/// Applies [`ARTIFACT_SEALS`]: the memfd can no longer change size or content, nor be unsealed.
pub fn seal(f: &File) -> io::Result<()> {
    // SAFETY: fcntl on a descriptor we own.
    if unsafe { libc::fcntl(f.as_raw_fd(), libc::F_ADD_SEALS, ARTIFACT_SEALS) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The seals on `fd` (`F_GET_SEALS`).
pub fn seals(fd: BorrowedFd<'_>) -> io::Result<libc::c_int> {
    // SAFETY: fcntl on a borrowed, open descriptor.
    let s = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
    if s < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(s)
    }
}

/// Receiver side: `fd` carries every artifact seal and holds exactly `len` bytes.
pub fn check_sealed(fd: BorrowedFd<'_>, len: u64) -> io::Result<()> {
    let s = seals(fd)?;
    if s & ARTIFACT_SEALS != ARTIFACT_SEALS {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "memfd is not sealed"));
    }
    let f = File::from(fd.try_clone_to_owned()?);
    if f.metadata()?.len() != len {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "memfd size differs from the announced length"));
    }
    Ok(())
}

/// A fresh sealed memfd with the first `len` bytes of `src`, read with `pread` (offsets explicit, so
/// `src`'s shared file offset is never used or moved).
pub fn copy_sealed(src: &File, len: u64, name: &CStr) -> io::Result<File> {
    let dst = memfd(name)?;
    let mut buf = vec![0u8; 1 << 16];
    let mut off = 0u64;
    while off < len {
        let want = buf.len().min((len - off) as usize);
        let n = src.read_at(&mut buf[..want], off)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        dst.write_all_at(&buf[..n], off)?;
        off += n as u64;
    }
    seal(&dst)?;
    Ok(dst)
}

/// Checks that `fd` is a connected `AF_UNIX` `SOCK_STREAM` socket (a job's socket).
pub fn is_unix_stream(fd: BorrowedFd<'_>) -> bool {
    let get = |opt| {
        let mut v: libc::c_int = 0;
        let mut l = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: getsockopt into a c_int-sized buffer on a borrowed descriptor.
        let r = unsafe { libc::getsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, opt, (&mut v as *mut libc::c_int).cast(), &mut l) };
        (r == 0).then_some(v)
    };
    get(libc::SO_DOMAIN) == Some(libc::AF_UNIX) && get(libc::SO_TYPE) == Some(libc::SOCK_STREAM)
}

/// Sets `O_NONBLOCK` (needed before handing a received socket to tokio).
pub fn set_nonblocking(fd: &impl AsFd) -> io::Result<()> {
    let raw = fd.as_fd().as_raw_fd();
    // SAFETY: fcntl on a descriptor the caller owns.
    unsafe {
        let flags = libc::fcntl(raw, libc::F_GETFL);
        if flags < 0 || libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, Write};
    use zkminer_witness::ipc::{read_frame, write_frame, KIND_CONTROL};

    #[test]
    fn a_sealed_memfd_round_trips_over_a_socketpair() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut m = memfd(c"t").unwrap();
        m.write_all(b"artifact bytes").unwrap();
        seal(&m).unwrap();
        send_with_fd(&a, KIND_CONTROL, b"{}", Some(m.as_fd())).unwrap();
        drop(m);
        let f = recv_with_fd(&b, 1024).unwrap().unwrap();
        assert_eq!((f.kind, &f.payload[..]), (KIND_CONTROL, &b"{}"[..]));
        let fd = f.fd.expect("the fd arrives with the frame");
        // The seals hold on the received descriptor: no writes, no growth, no shrinking, no unsealing.
        assert_eq!(seals(fd.as_fd()).unwrap() & ARTIFACT_SEALS, ARTIFACT_SEALS);
        check_sealed(fd.as_fd(), 14).unwrap();
        assert!(check_sealed(fd.as_fd(), 15).is_err());
        let mut file = File::from(fd);
        assert!(file.write_all(b"x").is_err(), "F_SEAL_WRITE");
        assert!(file.set_len(1).is_err(), "F_SEAL_SHRINK");
        assert!(file.set_len(100).is_err(), "F_SEAL_GROW");
        // SAFETY: fcntl on an owned descriptor.
        assert!(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, 0) } < 0, "F_SEAL_SEAL");
        // The receiver reads from offset 0 (the sender's writes moved the shared offset; read_at
        // does not care).
        let mut out = vec![0u8; 14];
        file.read_exact_at(&mut out, 0).unwrap();
        assert_eq!(&out, b"artifact bytes");
        let copy = copy_sealed(&file, 14, c"c").unwrap();
        let mut s = String::new();
        let mut copy2 = &copy;
        copy2.rewind().unwrap();
        copy2.read_to_string(&mut s).unwrap();
        assert_eq!(s, "artifact bytes");
        check_sealed(copy.as_fd(), 14).unwrap();
        // An unsealed memfd fails the receiver's check.
        let unsealed = memfd(c"u").unwrap();
        assert!(check_sealed(unsealed.as_fd(), 0).is_err());
    }

    #[test]
    fn frames_without_fds_and_interop_with_plain_frames() {
        let (a, b) = UnixStream::pair().unwrap();
        send_with_fd(&a, 7, b"abc", None).unwrap();
        let f = recv_with_fd(&b, 10).unwrap().unwrap();
        assert!(f.fd.is_none());
        assert_eq!(f.payload, b"abc");
        // A plain write_frame reads with recv_with_fd, and send_with_fd reads with read_frame.
        write_frame(&mut &a, 8, b"x").unwrap();
        assert_eq!(recv_with_fd(&b, 10).unwrap().unwrap().payload, b"x");
        send_with_fd(&a, 9, b"yz", None).unwrap();
        assert_eq!(read_frame(&mut &b, 10).unwrap(), (9, b"yz".to_vec()));
        drop(a);
        assert!(recv_with_fd(&b, 10).unwrap().is_none(), "clean close at a frame boundary");
    }

    #[test]
    fn large_frames_and_limits() {
        let (a, b) = UnixStream::pair().unwrap();
        let big = vec![0x5a; 3 << 20];
        let m = memfd(c"big").unwrap();
        let t = std::thread::spawn(move || {
            send_with_fd(&a, 1, &big, Some(m.as_fd())).unwrap();
            send_with_fd(&a, 2, b"next", None).unwrap();
            a
        });
        let f = recv_with_fd(&b, 4 << 20).unwrap().unwrap();
        assert_eq!(f.payload.len(), 3 << 20);
        assert!(f.fd.is_some());
        let g = recv_with_fd(&b, 10).unwrap().unwrap();
        assert!(g.fd.is_none() && g.payload == b"next");
        let a = t.join().unwrap();
        send_with_fd(&a, 1, &[0; 11], None).unwrap();
        assert!(matches!(recv_with_fd(&b, 10), Err(FrameError::TooLarge { len: 11, max: 10 })));
    }

    #[test]
    fn misplaced_or_extra_fds_are_refused_and_closed() {
        let (a, b) = UnixStream::pair().unwrap();
        // An fd attached to a payload byte, not the header.
        let m = memfd(c"late").unwrap();
        a.write_all_header(1, 4);
        sendmsg_once(a.as_raw_fd(), b"abcd", Some(m.as_raw_fd())).unwrap();
        assert!(matches!(recv_with_fd(&b, 10), Err(FrameError::Malformed)));
        // Two fds on one frame.
        let n = memfd(c"two").unwrap();
        let mut cbuf = [0u64; 4];
        let header = [1u8, 0, 0, 0, 0];
        let mut iov = libc::iovec { iov_base: header.as_ptr() as *mut _, iov_len: 5 };
        // SAFETY: as in sendmsg_once, with two ints of payload.
        unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cbuf.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(8) as _;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(8) as _;
            let d = libc::CMSG_DATA(c).cast::<RawFd>();
            std::ptr::write_unaligned(d, m.as_raw_fd());
            std::ptr::write_unaligned(d.add(1), n.as_raw_fd());
            assert_eq!(libc::sendmsg(a.as_raw_fd(), &msg, 0), 5);
        }
        assert!(matches!(recv_with_fd(&b, 10), Err(FrameError::Malformed)));
    }

    /// More fds than the reader's control buffer holds: the kernel sets `MSG_CTRUNC` (and closes
    /// what did not fit); the frame is refused and every fd that did arrive is closed. Checked
    /// through a pipe: its read end sees EOF only once every copy of the write end is closed.
    #[test]
    fn truncated_ancillary_data_is_refused_and_every_fd_closed() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut p = [0 as RawFd; 2];
        // SAFETY: pipe2 into a 2-int array.
        assert_eq!(unsafe { libc::pipe2(p.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) }, 0);
        // SAFETY: both ends are fresh descriptors owned here.
        let (rd, wr) = unsafe { (OwnedFd::from_raw_fd(p[0]), OwnedFd::from_raw_fd(p[1])) };
        const N: usize = 64;
        let copies: Vec<OwnedFd> = (0..N).map(|_| wr.try_clone().unwrap()).collect();
        drop(wr);
        let header = [1u8, 0, 0, 0, 0];
        let mut iov = libc::iovec { iov_base: header.as_ptr() as *mut _, iov_len: 5 };
        let mut cbuf = vec![0u64; 64];
        // SAFETY: one SCM_RIGHTS message of N ints in a buffer of 512 bytes (CMSG_SPACE(256) fits).
        unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cbuf.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE((N * 4) as u32) as _;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN((N * 4) as u32) as _;
            let d = libc::CMSG_DATA(c).cast::<RawFd>();
            for (i, f) in copies.iter().enumerate() {
                std::ptr::write_unaligned(d.add(i), f.as_raw_fd());
            }
            assert_eq!(libc::sendmsg(a.as_raw_fd(), &msg, 0), 5);
        }
        drop(copies);
        match recv_with_fd(&b, 10) {
            Err(FrameError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            other => panic!("accepted a truncated control message: {other:?}"),
        }
        let mut byte = [0u8; 1];
        // SAFETY: read into a 1-byte buffer from the pipe's read end.
        let n = unsafe { libc::read(rd.as_raw_fd(), byte.as_mut_ptr().cast(), 1) };
        assert_eq!(n, 0, "EOF: no copy of the write end survived ({})", io::Error::last_os_error());
    }

    #[tokio::test]
    async fn async_halves_interoperate_with_blocking_ones() {
        let (a, b) = UnixStream::pair().unwrap();
        b.set_nonblocking(true).unwrap();
        let b = tokio::net::UnixStream::from_std(b).unwrap();
        let t = std::thread::spawn(move || {
            let m = memfd(c"x").unwrap();
            send_with_fd(&a, 3, &vec![1u8; 200_000], Some(m.as_fd())).unwrap();
            let back = recv_with_fd(&a, 1 << 20).unwrap().unwrap();
            assert!(back.fd.is_some() && back.payload == b"pong");
        });
        let f = recv_with_fd_async(&b, 1 << 20).await.unwrap().unwrap();
        assert_eq!(f.payload.len(), 200_000);
        let fd = f.fd.unwrap();
        assert!(!is_unix_stream(fd.as_fd()));
        send_with_fd_async(&b, 4, b"pong", Some(fd.as_fd())).await.unwrap();
        t.join().unwrap();
        let (s, _peer) = UnixStream::pair().unwrap();
        assert!(is_unix_stream(s.as_fd()));
    }

    trait HeaderWrite {
        fn write_all_header(&self, kind: u8, len: u32);
    }
    impl HeaderWrite for UnixStream {
        fn write_all_header(&self, kind: u8, len: u32) {
            let mut h = vec![kind];
            h.extend_from_slice(&len.to_be_bytes());
            (&*self).write_all(&h).unwrap();
        }
    }
}
