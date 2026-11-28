// SPDX-License-Identifier: Apache-2.0

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
};

use uuid::Uuid;

pub(crate) fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|directory| !directory.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

pub(crate) fn write(path: &Path, data: &[u8], replace: bool) -> io::Result<()> {
    let temporary = parent(path).join(format!(".context-forge-{}.tmp", Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    let result = (|| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(data)?;
        file.sync_all()
    })();
    drop(file);
    let result = result.and_then(|()| {
        if replace {
            fs::rename(&temporary, path)
        } else {
            fs::hard_link(&temporary, path)
        }
    });
    let _ = fs::remove_file(&temporary);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_keeps_existing_private_file_and_removes_staging_file() {
        let directory = std::env::temp_dir().join(format!("context-forge-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("secrets");
        write(&path, b"created", false).unwrap();
        let conflict = write(&path, b"other", false).unwrap_err();
        assert_eq!(conflict.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), b"created");
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        write(&path, b"replacement", true).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(directory).unwrap();
    }
}
