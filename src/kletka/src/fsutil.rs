use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::process::{Command, Stdio};

pub fn thin_copy(src: &Path, dst: &Path) -> io::Result<()> {
    let _ = std::fs::remove_file(dst);

    let output = Command::new("cp")
        .arg("--reflink=auto")
        .arg("--sparse=always")
        .arg(src)
        .arg(dst)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;

    if output.status.success() {
        return Ok(());
    }

    Err(io::Error::other(format!(
        "copying {} to {} failed: {}",
        src.display(),
        dst.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

pub fn disk_usage(path: &Path) -> io::Result<u64> {
    Ok(std::fs::metadata(path)?.blocks() * 512)
}

pub fn ext4_size(path: &Path) -> io::Result<u64> {
    let output = Command::new("dumpe2fs")
        .arg("-h")
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()?;

    if !output.status.success() {
        return Err(io::Error::other(format!(
            "reading the ext4 superblock of {} failed: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let text = String::from_utf8_lossy(&output.stdout);

    let field = |name: &str| -> io::Result<u64> {
        text.lines()
            .rfind(|line| line.trim_start().starts_with(name))
            .and_then(|line| line.split(':').nth(1))
            .and_then(|value| value.trim().parse().ok())
            .ok_or_else(|| {
                io::Error::other(format!(
                    "unexpected dumpe2fs output for {}: missing '{name}'",
                    path.display()
                ))
            })
    };

    let block_count = field("Block count")?;
    let block_size = field("Block size")?;

    Ok(block_count * block_size)
}

pub fn grow_ext4(path: &Path, target_bytes: u64) -> io::Result<()> {
    let current = ext4_size(path)?;

    if target_bytes < current {
        return Err(io::Error::other(format!(
            "cannot shrink {} from {} to {} bytes",
            path.display(),
            current,
            target_bytes
        )));
    }

    if target_bytes == current {
        return Ok(());
    }

    let file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.set_len(target_bytes)?;
    drop(file);

    let output = Command::new("resize2fs")
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;

    if output.status.success() {
        return Ok(());
    }

    Err(io::Error::other(format!(
        "growing {} to {} bytes failed: {}",
        path.display(),
        target_bytes,
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write as _};
    use std::path::PathBuf;

    use super::*;
    use crate::system::test_util::TempDir;

    fn sparse_source(dir: &TempDir, name: &str) -> PathBuf {
        let path = dir.path().join(name);
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"kletka-header").unwrap();
        file.seek(SeekFrom::Start(4 * 1024 * 1024 - 16)).unwrap();
        file.write_all(b"kletka-tail").unwrap();
        path
    }

    #[test]
    fn thin_copy_preserves_content_and_holes() {
        let dir = TempDir::new("fsutil-thin");
        let src = sparse_source(&dir, "src.ext4");
        let dst = dir.path().join("dst.ext4");
        let len = std::fs::metadata(&src).unwrap().len();

        thin_copy(&src, &dst).unwrap();

        assert_eq!(std::fs::read(&dst).unwrap(), std::fs::read(&src).unwrap());
        assert_eq!(std::fs::metadata(&dst).unwrap().len(), len);
        assert!(
            disk_usage(&dst).unwrap() < len / 2,
            "expected a thin copy, got {} of {} bytes",
            disk_usage(&dst).unwrap(),
            len
        );
    }

    #[test]
    fn thin_copy_replaces_existing_destination() {
        let dir = TempDir::new("fsutil-replace");
        let src = sparse_source(&dir, "src.ext4");
        let dst = dir.path().join("dst.ext4");

        std::fs::write(&dst, vec![0u8; 4096]).unwrap();
        thin_copy(&src, &dst).unwrap();

        assert_eq!(std::fs::read(&dst).unwrap(), std::fs::read(&src).unwrap());
    }

    #[test]
    fn thin_copy_fails_for_missing_source() {
        let dir = TempDir::new("fsutil-missing");
        let err = thin_copy(&dir.path().join("absent"), &dir.path().join("dst")).unwrap_err();
        assert!(err.to_string().contains("absent"), "{err}");
    }

    fn have_e2fsprogs() -> bool {
        ["mkfs.ext4", "resize2fs", "dumpe2fs"].iter().all(|binary| {
            std::env::var_os("PATH").is_some_and(|paths| {
                std::env::split_paths(&paths).any(|dir| dir.join(binary).is_file())
            })
        })
    }

    fn small_ext4(dir: &TempDir, name: &str) -> PathBuf {
        let path = dir.path().join(name);
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(16 * 1024 * 1024).unwrap();
        drop(file);

        let status = std::process::Command::new("mkfs.ext4")
            .args(["-q", "-F"])
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());

        path
    }

    #[test]
    fn ext4_size_reads_superblock() {
        if !have_e2fsprogs() {
            return;
        }

        let dir = TempDir::new("fsutil-ext4size");
        let img = small_ext4(&dir, "disk.ext4");

        assert_eq!(ext4_size(&img).unwrap(), 16 * 1024 * 1024);
    }

    #[test]
    fn grow_ext4_grows_sparsely_and_refuses_shrink() {
        if !have_e2fsprogs() {
            return;
        }

        let dir = TempDir::new("fsutil-grow");
        let img = small_ext4(&dir, "disk.ext4");

        grow_ext4(&img, 32 * 1024 * 1024).unwrap();
        assert_eq!(ext4_size(&img).unwrap(), 32 * 1024 * 1024);
        assert_eq!(std::fs::metadata(&img).unwrap().len(), 32 * 1024 * 1024);
        assert!(
            disk_usage(&img).unwrap() < 16 * 1024 * 1024,
            "grown tail must stay sparse, got {}",
            disk_usage(&img).unwrap()
        );

        grow_ext4(&img, 32 * 1024 * 1024).unwrap();

        let err = grow_ext4(&img, 8 * 1024 * 1024).unwrap_err();
        assert!(err.to_string().contains("cannot shrink"), "{err}");
        assert_eq!(ext4_size(&img).unwrap(), 32 * 1024 * 1024);
    }
}
