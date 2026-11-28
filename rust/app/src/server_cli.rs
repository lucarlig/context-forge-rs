// SPDX-License-Identifier: Apache-2.0

use std::{future::Future, io, net::SocketAddr, path::PathBuf};

use axum::Router;
use clap::Parser;
use context_forge_rs::{config::Settings, http_boundary::HttpBoundary};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

#[cfg(unix)]
use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt},
};
#[cfg(unix)]
use tokio::net::UnixListener;

#[cfg(unix)]
mod inherited;
#[cfg(unix)]
pub(crate) use inherited::InheritedListener;

#[derive(Parser)]
#[command(
    name = "context-forge-rs",
    version,
    about = "Run the ContextForge gateway"
)]
#[command(after_help = "Other commands:
  migrate              Upgrade the native database schema
  export               Export gateway configuration
  import               Import gateway configuration
  --validate-config    Validate an environment file (default: .env)
  --config-schema      Print the configuration JSON Schema or write it to a file
  --support-bundle     Create a sanitized diagnostic ZIP archive
  init-secrets         Generate deployment secrets
  rotate-credentials   Rotate stored credentials")]
pub(crate) struct ServerArgs {
    /// TCP address. Defaults to HOST or MCG_HOST, then 127.0.0.1.
    #[arg(long, value_name = "HOST")]
    pub(crate) host: Option<String>,

    /// TCP port. Defaults to PORT or MCG_PORT, then 4444. Use 0 for an available port.
    #[arg(long, value_name = "PORT")]
    pub(crate) port: Option<u16>,

    /// Read additional gateway settings from this environment file.
    #[arg(long, value_name = "PATH", value_parser = env_file_path())]
    pub(crate) env_file: Option<PathBuf>,

    /// Listen on a Unix domain socket.
    #[cfg(unix)]
    #[arg(long, value_name = "PATH")]
    pub(crate) uds: Option<PathBuf>,

    /// Accept connections from a stream socket passed by the launcher.
    #[cfg(unix)]
    #[arg(long, value_name = "FD", value_parser = clap::value_parser!(i32).range(0..))]
    pub(crate) fd: Option<std::os::fd::RawFd>,
}

fn env_file_path() -> impl clap::builder::TypedValueParser<Value = PathBuf> {
    use clap::builder::{PathBufValueParser, TypedValueParser};

    PathBufValueParser::new().try_map(|path| {
        if path.metadata()?.is_file() {
            Ok(path)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected a regular file",
            ))
        }
    })
}

pub(crate) enum ServerListener {
    Tcp(TcpListener, SocketAddr),
    #[cfg(unix)]
    Unix(UnixListener, Option<SocketFile>),
}

impl ServerListener {
    pub(crate) async fn bind(
        settings: &Settings,
        #[cfg(unix)] path: Option<PathBuf>,
        #[cfg(unix)] inherited: Option<InheritedListener>,
    ) -> io::Result<Self> {
        #[cfg(unix)]
        if let Some(listener) = inherited {
            return match listener {
                InheritedListener::Tcp(listener) => {
                    let address = listener.local_addr()?;
                    Ok(Self::Tcp(TcpListener::from_std(listener)?, address))
                }
                InheritedListener::Unix(listener) => {
                    Ok(Self::Unix(UnixListener::from_std(listener)?, None))
                }
            };
        }
        #[cfg(unix)]
        if let Some(path) = path {
            let listener = UnixListener::bind(&path)?;
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.file_type().is_socket() {
                return Err(io::Error::other("listener path no longer names a socket"));
            }
            return Ok(Self::Unix(
                listener,
                Some(SocketFile {
                    path,
                    device: metadata.dev(),
                    inode: metadata.ino(),
                }),
            ));
        }

        if settings.host.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "listener host must be nonempty",
            ));
        }
        let listener = TcpListener::bind((settings.host.as_str(), settings.port)).await?;
        let address = listener.local_addr()?;
        Ok(Self::Tcp(listener, address))
    }

    pub(crate) fn port(&self) -> Option<u16> {
        match self {
            Self::Tcp(_, address) => Some(address.port()),
            #[cfg(unix)]
            Self::Unix(..) => None,
        }
    }

    pub(crate) async fn serve<T>(
        self,
        boundary: HttpBoundary,
        router: Router,
        shutdown: CancellationToken,
        background: impl Future<Output = T>,
    ) -> T {
        match self {
            Self::Tcp(listener, address) => {
                tracing::info!(%address, "gateway listening");
                boundary.serve(listener, router, shutdown, background).await
            }
            #[cfg(unix)]
            Self::Unix(listener, socket) => {
                tracing::info!(address = ?listener.local_addr(), "gateway listening");
                let result = boundary
                    .serve_unix(listener, router, shutdown, background)
                    .await;
                drop(socket);
                result
            }
        }
    }
}

#[cfg(unix)]
pub(crate) struct SocketFile {
    path: PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl Drop for SocketFile {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.file_type().is_socket()
                && self.device == metadata.dev()
                && self.inode == metadata.ino()
        }) && let Err(error) = fs::remove_file(&self.path)
        {
            tracing::warn!(path = %self.path.display(), %error, "could not remove listener socket");
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn unix_listener_preserves_existing_and_replacement_paths() {
        let directory =
            std::env::temp_dir().join(format!("cf-{:x}", Uuid::new_v4().as_u64_pair().0));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("sock");
        let settings = Settings::from_env_with_listener(Some("127.0.0.1".into()), Some(0)).unwrap();

        fs::write(&path, "keep").unwrap();
        assert!(
            ServerListener::bind(&settings, Some(path.clone()), None)
                .await
                .is_err()
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "keep");
        fs::remove_file(&path).unwrap();

        let listener = ServerListener::bind(&settings, Some(path.clone()), None)
            .await
            .unwrap();
        assert!(
            ServerListener::bind(&settings, Some(path.clone()), None)
                .await
                .is_err()
        );
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
        let original = directory.join("old");
        fs::rename(&path, &original).unwrap();
        fs::write(&path, "replacement").unwrap();
        drop(listener);
        assert_eq!(fs::read_to_string(&path).unwrap(), "replacement");
        fs::remove_dir_all(directory).unwrap();
    }
}
