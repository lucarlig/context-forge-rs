// SPDX-License-Identifier: Apache-2.0

use std::{
    io,
    mem::{MaybeUninit, size_of, size_of_val},
    net::TcpListener,
    os::{
        fd::{FromRawFd, OwnedFd, RawFd},
        unix::net::UnixListener,
    },
};

pub(crate) enum InheritedListener {
    Tcp(TcpListener),
    Unix(UnixListener),
}

impl InheritedListener {
    /// # Safety
    ///
    /// The launcher transfers the descriptor to the gateway before runtime startup.
    pub(crate) unsafe fn adopt(fd: RawFd) -> io::Result<Self> {
        // SAFETY: F_GETFD takes only the descriptor and checks its validity.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: The launcher transfers a valid descriptor under the caller's contract.
        let descriptor = unsafe { OwnedFd::from_raw_fd(fd) };
        if socket_option(fd, libc::SO_TYPE)? != libc::SOCK_STREAM {
            return Err(invalid("expected a stream socket"));
        }
        let family = socket_family(fd)?;
        if !matches!(family, libc::AF_INET | libc::AF_INET6 | libc::AF_UNIX) {
            return Err(invalid("expected a TCP or Unix stream socket"));
        }
        // SAFETY: F_SETFD takes an integer descriptor flag mask.
        check(unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) })?;
        // SAFETY: listen takes a descriptor and backlog value and checks socket state.
        check(unsafe { libc::listen(fd, 2048) })?;

        if family == libc::AF_UNIX {
            let listener = UnixListener::from(descriptor);
            listener.set_nonblocking(true)?;
            Ok(Self::Unix(listener))
        } else {
            let listener = TcpListener::from(descriptor);
            listener.set_nonblocking(true)?;
            Ok(Self::Tcp(listener))
        }
    }
}

fn socket_option(fd: RawFd, option: libc::c_int) -> io::Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut len = size_of_val(&value) as libc::socklen_t;
    // SAFETY: The output pointers stay valid for the declared integer and length.
    check(unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            std::ptr::from_mut(&mut value).cast(),
            &mut len,
        )
    })?;
    if len as usize != size_of_val(&value) {
        return Err(invalid("unexpected socket option length"));
    }
    Ok(value)
}

fn socket_family(fd: RawFd) -> io::Result<libc::c_int> {
    let mut address = MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: sockaddr_storage is valid, aligned output storage for every socket family.
    check(unsafe { libc::getsockname(fd, address.as_mut_ptr().cast(), &mut len) })?;
    // SAFETY: The unwritten fields remain zeroed and the kernel filled the family.
    Ok(unsafe { address.assume_init() }.ss_family.into())
}

fn check(status: libc::c_int) -> io::Result<()> {
    if status == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsRawFd, IntoRawFd};

    use super::*;

    #[test]
    fn inherited_listener_is_owned_nonblocking_and_close_on_exec() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let fd = listener.into_raw_fd();
        // SAFETY: The test relinquished the listener and keeps the descriptor open.
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, 0);
        // SAFETY: This test transfers the descriptor and has no other owner.
        let InheritedListener::Tcp(listener) = (unsafe { InheritedListener::adopt(fd) }).unwrap()
        else {
            panic!("expected an inherited TCP listener");
        };
        assert_eq!(listener.local_addr().unwrap(), address);
        let fd = listener.as_raw_fd();
        // SAFETY: The listener owns the descriptor for the duration of these reads.
        let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_eq!(descriptor_flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
        // SAFETY: F_GETFL reads the flags of the still-owned descriptor.
        let status_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert_eq!(status_flags & libc::O_NONBLOCK, libc::O_NONBLOCK);
    }
}
