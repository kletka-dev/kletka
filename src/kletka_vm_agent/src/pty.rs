use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Stdio;

pub struct Pty {
    read: tokio::fs::File,
    write: tokio::fs::File,
    ioctl_fd: OwnedFd,
}

pub struct PtyResize {
    fd: OwnedFd,
}

pub struct PtySlave {
    fd: OwnedFd,
}

fn open_raw(path: &std::ffi::CStr, flags: i32) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::open(path.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn resize_fd(fd: &OwnedFd, cols: u16, rows: u16) {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let _ = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
}

impl Pty {
    pub fn open(cols: u16, rows: u16) -> io::Result<(Pty, PtySlave)> {
        let master = open_raw(c"/dev/ptmx", libc::O_RDWR | libc::O_NOCTTY)?;
        let mut n: libc::c_int = 0;
        if unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCGPTN, &mut n) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut unlock: libc::c_int = 0;
        if unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSPTLCK, &mut unlock) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let slave_path = format!("/dev/pts/{n}\0");
        let slave_path =
            std::ffi::CString::from_vec_with_nul(slave_path.into_bytes()).expect("nul-terminated");
        let slave = open_raw(&slave_path, libc::O_RDWR | libc::O_NOCTTY)?;

        resize_fd(&master, cols, rows);
        Ok((
            Pty {
                read: tokio::fs::File::from(std::fs::File::from(master.try_clone()?)),
                write: tokio::fs::File::from(std::fs::File::from(master.try_clone()?)),
                ioctl_fd: master,
            },
            PtySlave { fd: slave },
        ))
    }

    pub fn split(self) -> (tokio::fs::File, tokio::fs::File, PtyResize) {
        let Pty {
            read,
            write,
            ioctl_fd,
        } = self;
        (read, write, PtyResize { fd: ioctl_fd })
    }
}

impl PtyResize {
    pub fn apply(&self, cols: u16, rows: u16) {
        resize_fd(&self.fd, cols, rows);
    }
}

impl PtySlave {
    pub fn into_stdio(self) -> io::Result<[Stdio; 3]> {
        Ok([
            Stdio::from(self.fd.try_clone()?),
            Stdio::from(self.fd.try_clone()?),
            Stdio::from(self.fd),
        ])
    }

    pub fn become_controlling_tty() -> io::Result<()> {
        if unsafe { libc::setsid() } < 0 {
            return Err(io::Error::last_os_error());
        }
        let _ = unsafe { libc::ioctl(0, libc::TIOCSCTTY, 0) };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tokio::io::AsyncReadExt as _;

    #[tokio::test]
    async fn opens_with_the_requested_size_and_resizes() {
        if !std::path::Path::new("/dev/ptmx").exists() {
            return;
        }

        for (cols, rows) in [(31u16, 13u16), (99, 42)] {
            let (pty, slave) = Pty::open(cols, rows).unwrap();
            let [stdin, stdout, stderr] = slave.into_stdio().unwrap();
            let mut child = Command::new("stty")
                .arg("size")
                .stdin(stdin)
                .stdout(stdout)
                .stderr(stderr)
                .spawn()
                .expect("spawn stty");

            let (mut read, _write, _resize) = pty.split();
            let mut out = Vec::new();
            loop {
                let mut buf = [0u8; 128];
                match read.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => out.extend_from_slice(&buf[..n]),
                }
            }
            let _ = child.wait();
            assert_eq!(
                String::from_utf8_lossy(&out).trim(),
                format!("{rows} {cols}")
            );
        }
    }
}
