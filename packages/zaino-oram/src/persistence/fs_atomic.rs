use std::{
    fmt,
    fs::{self, File},
    io,
    path::Path,
};

use tempfile::{Builder as TempfileBuilder, NamedTempFile};

/// A directory path either failed an I/O operation or was not a real directory.
#[derive(Debug)]
pub(crate) enum RealDirectoryError {
    /// A filesystem operation failed.
    Io(io::Error),
    /// The path or its parent was not a real directory.
    UnsafePath,
}

impl fmt::Display for RealDirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => f.write_str("directory filesystem operation failed"),
            Self::UnsafePath => f.write_str("path is not a real directory"),
        }
    }
}

impl std::error::Error for RealDirectoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::UnsafePath => None,
        }
    }
}

/// Creates a uniquely named temporary file inside `directory`.
pub(crate) fn create_unique_file(directory: &Path, label: &str) -> io::Result<NamedTempFile> {
    let prefix = format!(".{label}.");
    TempfileBuilder::new()
        .prefix(&prefix)
        .suffix(".tmp")
        .tempfile_in(directory)
}

/// Synchronizes directory metadata to durable storage.
pub(crate) fn sync_directory(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}

/// Ensures `directory` exists without accepting a symlink or non-directory.
pub(crate) fn ensure_real_directory(directory: &Path) -> Result<(), RealDirectoryError> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_dir() => return Ok(()),
        Ok(_) => return Err(RealDirectoryError::UnsafePath),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(RealDirectoryError::Io(error)),
    }

    let parent = match directory
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        Some(parent) => parent,
        None => Path::new("."),
    };
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|_| RealDirectoryError::UnsafePath)?;
    if !parent_metadata.file_type().is_dir() {
        return Err(RealDirectoryError::UnsafePath);
    }

    match fs::create_dir(directory) {
        Ok(()) => sync_directory(parent).map_err(RealDirectoryError::Io)?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(RealDirectoryError::Io(error)),
    }
    let metadata = fs::symlink_metadata(directory).map_err(RealDirectoryError::Io)?;
    if !metadata.file_type().is_dir() {
        return Err(RealDirectoryError::UnsafePath);
    }
    Ok(())
}
