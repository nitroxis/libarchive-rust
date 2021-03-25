use std::ffi::{CStr, CString};
use std::str;
use std::{default::Default, path::Path};

use error::ErrCode;
use libarchive3_sys::ffi;

#[derive(Debug, PartialEq, Eq)]
pub enum ReadCompression {
    All,
    Bzip2,
    Compress,
    Gzip,
    Lzip,
    Lzma,
    None,
    Program(String),
    Rpm,
    Uu,
    Xz,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReadFormat {
    SevenZip,
    All,
    Ar,
    Cab,
    Cpio,
    Empty,
    Gnutar,
    Iso9660,
    Lha,
    Mtree,
    Rar,
    Raw,
    Tar,
    Xar,
    Zip,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReadFilter {
    All,
    Bzip2,
    Compress,
    Gzip,
    Grzip,
    Lrzip,
    Lzip,
    Lzma,
    Lzop,
    None,
    Program(String),
    ProgramSignature(String, Option<extern "C" fn() -> ()>, usize),
    Rpm,
    Uu,
    Xz,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WriteFormat {
    SevenZip,
    ArBsd,
    ArSvr4,
    Cpio,
    CpioNewc,
    Gnutar,
    Iso9660,
    Mtree,
    MtreeClassic,
    Pax,
    PaxRestricted,
    Shar,
    SharDump,
    Ustar,
    V7tar,
    Xar,
    Zip,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WriteFilter {
    B64Encode,
    Bzip2,
    Compress,
    Grzip,
    Gzip,
    Lrzip,
    Lzip,
    Lzma,
    Lzop,
    None,
    Program(String),
    UuEncode,
    Xz,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FileType {
    BlockDevice,
    SymbolicLink,
    Socket,
    CharacterDevice,
    Directory,
    NamedPipe,
    Mount,
    RegularFile,
}

/// The trait representing a handle to a libarchive archive.
///
/// # Safety
/// Implementors of this trait **must** call the function to free the handle before they go out of
/// scope. I'd recommend using the `Drop` trait for this.
pub trait Handle {
    /// Returns a *const to the interal `archive` c struct
    ///
    /// # Safety
    /// This pointer dangles once the `archive` has been deallocated.
    unsafe fn handle(&self) -> *const ffi::Struct_archive;

    /// Returns a *mut to the interal `archive` c struct
    ///
    /// # Safety
    /// This pointer dangles once the `archive` has been deallocated.
    unsafe fn handle_mut(&mut self) -> *mut ffi::Struct_archive;

    /// Get the error code from the most recent libarchive function call
    fn err_code(&self) -> ErrCode {
        // SAFETY: Casting to *mut because these c functions take T* not const T*. They do not
        // modify the pointer, so this is sound.
        let code = unsafe { ffi::archive_errno(self.handle() as *mut _) };
        ErrCode(code)
    }

    /// Get a str containing the error message from the most recent libarchive function call
    fn err_msg(&self) -> &str {
        // SAFETY: Casting to *mut because these c functions take T* not const T*. They do not
        // modify the pointer, so this is sound.
        let c_str = unsafe { CStr::from_ptr(ffi::archive_error_string(self.handle() as *mut _)) };
        c_str.to_str().unwrap()
    }
}

/// The trait representing an `archive_entry`
///
/// # Safety
/// See [`Handle`](trait.Handle.html)
pub trait Entry {
    /// Gives a *const to the internal `archive_entry` c struct
    ///
    /// # Safety
    /// The pointer returned here points into the `archive` struct. As lifetimes are not capable of
    /// expressing self-referential structs (yet?) this must all be unsafe. This pointer dangles 
    /// if the `archive` struct held by the implementor of `Handle` is deallocated.
    ///
    /// Most (all?) of the functions in libarchive take `T*`, not `const T*`, so this `*const` will
    /// probably have to be cast to a `*mut` to use it. Do not pass that `*mut` to a function that may
    /// modify it, as that is UB.
    unsafe fn entry(&self) -> *const ffi::Struct_archive_entry;

    /// Gives a *mut to the internal `archive_entry` c struct.
    ///
    /// # Safety
    /// The pointer returned here points into the archive struct. As lifetimes are not capable of
    /// expressing self-referential structs (yet?) this must all be unsafe. This pointer dangles
    /// if the `archive` struct held by the implementor of `Handle` is deallocated.
    unsafe fn entry_mut(&mut self) -> *mut ffi::Struct_archive_entry;

    /// Get the filetype of the entry.
    fn filetype(&self) -> FileType {
        // SAFETY: Casting to *mut because these c functions take T* not const T*. They do not
        // modify the pointer, so this is sound.
        match unsafe { ffi::archive_entry_filetype(self.entry() as *mut _) } as u32 {
            ffi::AE_IFBLK => FileType::BlockDevice,
            ffi::AE_IFCHR => FileType::CharacterDevice,
            ffi::AE_IFLNK => FileType::SymbolicLink,
            ffi::AE_IFDIR => FileType::Directory,
            ffi::AE_IFIFO => FileType::NamedPipe,
            ffi::AE_IFMT => FileType::Mount,
            ffi::AE_IFREG => FileType::RegularFile,
            ffi::AE_IFSOCK => FileType::Socket,
            code => unreachable!("undefined filetype: {}", code),
        }
    }

    /// Get the location of a hardlink, if it exists
    fn hardlink(&self) -> Option<&str> {
        let c_str: &CStr = unsafe {
            // SAFETY: Casting to *mut because these c functions take T* not const T*. They do not
            // modify the pointer, so this is sound.
            let ptr = ffi::archive_entry_hardlink(self.entry() as *mut _);
            if ptr.is_null() {
                return None;
            }
            CStr::from_ptr(ptr)
        };
        c_str.to_str().ok()
        //let buf: &[u8] = c_str.to_bytes();
        //Some(str::from_utf8(buf).unwrap())
    }

    /// Get the pathname of the file the entry refers to
    fn pathname(&self) -> &str {
        // SAFETY: Casting to *mut because these c functions take T* not const T*. They do not
        // modify the pointer, so this is sound.
        let c_str: &CStr =
            unsafe { CStr::from_ptr(ffi::archive_entry_pathname(self.entry() as *mut _)) };
        let buf: &[u8] = c_str.to_bytes();
        str::from_utf8(buf).unwrap()
    }

    /// Get the mode of the file
    fn mode(&self) -> u32 {
        // SAFETY: Casting to *mut because these c functions take T* not const T*. They do not
        // modify the pointer, so this is sound.
        unsafe { ffi::archive_entry_mode(self.entry() as *mut _) }
    }

    /// Get the id of the group that owns the file
    fn gid(&self) -> i64 {
        // SAFETY: Casting to *mut because these c functions take T* not const T*. They do not
        // modify the pointer, so this is sound.
        unsafe { ffi::archive_entry_gid(self.entry() as *mut _) }
    }

    /// Get the id of the user that owns the file
    fn uid(&self) -> i64 {
        // SAFETY: Casting to *mut because these c functions take T* not const T*. They do not
        // modify the pointer, so this is sound.
        unsafe { ffi::archive_entry_uid(self.entry() as *mut _) }
    }

    /// Get the `mtime` of the file (The time it was last modified) as a unix timestamp
    fn time(&self) -> i64 {
        // SAFETY: Casting to *mut because these c functions take T* not const T*. They do not
        // modify the pointer, so this is sound.
        unsafe { ffi::archive_entry_mtime(self.entry() as *mut _) }
    }

    /// Get the size of the file, in bytes
    fn size(&self) -> i64 {
        // SAFETY: Casting to *mut because these c functions take T* not const T*. They do not
        // modify the pointer, so this is sound.
        unsafe { ffi::archive_entry_size(self.entry() as *mut _) }
    }

    /// Get the destination of a symlink, if one exists
    fn symlink(&self) -> Option<&str> {
        match self.filetype() {
            FileType::SymbolicLink => {
                // SAFETY: Casting to *mut because these c functions take T* not const T*. They do not
                // modify the pointer, so this is sound.
                unsafe { CStr::from_ptr(ffi::archive_entry_symlink(self.entry() as *mut _)) }
                    .to_str()
                    .ok()
            }
            _ => None,
        }
    }

    /// Set the filetype of the file.
    fn set_filetype(&mut self, file_type: FileType) {
        let file_type = match file_type {
            FileType::BlockDevice => ffi::AE_IFBLK,
            FileType::CharacterDevice => ffi::AE_IFCHR,
            FileType::SymbolicLink => ffi::AE_IFLNK,
            FileType::Directory => ffi::AE_IFDIR,
            FileType::NamedPipe => ffi::AE_IFIFO,
            FileType::Mount => ffi::AE_IFMT,
            FileType::RegularFile => ffi::AE_IFREG,
            FileType::Socket => ffi::AE_IFSOCK,
        };
        unsafe {
            ffi::archive_entry_set_filetype(self.entry_mut(), file_type);
        }
    }

    /// Set the destination of a link
    fn set_link<P: AsRef<Path>>(&mut self, path: P) {
        unsafe {
            let c_str = CString::new(path.as_ref().to_str().unwrap()).unwrap();
            ffi::archive_entry_set_link(self.entry_mut(), c_str.as_ptr());
        }
    }

    /// Set the pathname of the file
    fn set_pathname<P: AsRef<Path>>(&mut self, path: P) {
        unsafe {
            let c_str = CString::new(path.as_ref().to_str().unwrap()).unwrap();
            ffi::archive_entry_set_pathname(self.entry_mut(), c_str.as_ptr());
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExtractOption {
    // The user and group IDs should be set on the restored file. By default, the user and group
    // IDs are not restored.
    Owner,
    // Full permissions (including SGID, SUID, and sticky bits) should be restored exactly as
    // specified, without obeying the current umask. Note that SUID and SGID bits can only be
    // restored if the user and group ID of the object on disk are correct. If
    // `ExtractOption::Owner` is not specified, then SUID and SGID bits will only be restored if
    // the default user and group IDs of newly-created objects on disk happen to match those
    // specified in the archive entry. By default, only basic permissions are restored, and umask
    // is obeyed.
    Permissions,
    // The timestamps (mtime, ctime, and atime) should be restored. By default, they are ignored.
    // Note that restoring of atime is not currently supported.
    Time,
    // Existing files on disk will not be overwritten. By default, existing regular files are
    // truncated and overwritten; existing directories will have their permissions updated; other
    // pre-existing objects are unlinked and recreated from scratch.
    NoOverwrite,
    // Existing files on disk will be unlinked before any attempt to create them. In some cases,
    // this can prove to be a significant performance improvement. By default, existing files are
    // truncated and rewritten, but the file is not recreated. In particular, the default behavior
    // does not break existing hard links.
    Unlink,
    // Attempt to restore ACLs. By default, extended ACLs are ignored.
    ACL,
    // Attempt to restore extended file flags. By default, file flags are ignored.
    FFlags,
    // Attempt to restore POSIX.1e extended attributes. By default, they are ignored.
    XAttr,
    // Refuse to extract any object whose final location would be altered by a symlink on disk.
    // This is intended to help guard against a variety of mischief caused by archives that
    // (deliberately or otherwise) extract files outside of the current directory. The default is
    // not to perform this check. If ARCHIVE_EXTRACT_UNLINK is specified together with this option,
    // the library will remove any intermediate symlinks it finds and return an error only if such
    // symlink could not be removed.
    SecureSymlinks,
    // Refuse to extract a path that contains a `..` element anywhere within it. The default is to
    // not refuse such paths. Note that paths ending in `..` always cause an error, regardless of
    // this flag.
    SecureNoDotDot,
    // Default: Create parent directories as needed
    NoAutoDir,
    // Default: Overwrite files, even if one on disk is newer
    NoOverwriteNewer,
    // Scan data for blocks of NUL bytes and try to recreate them with holes. This results in
    // sparse files, independent of whether the archive format supports or uses them.
    Sparse,
    // Default: Do not restore Mac extended metadata
    // This has no effect except on Mac OS
    MacMetadata,
    // Default: Use HFS+ compression if it was compressed
    // This has no effect except on Mac OS v10.6 or later
    NoHFSCompression,
    // Default: Do not use HFS+ compression if it was not compressed
    // This has no effect except on Mac OS v10.6 or later
    HFSCompressionForced,
    // Default: Do not reject entries with absolute paths
    SecureNoAbsolutePaths,
    // Default: Do not clear no-change flags when unlinking object
    ClearNoChangeFFlags,
}

pub struct ExtractOptions {
    pub flags: i32,
}

impl ExtractOptions {
    pub fn new() -> Self {
        ExtractOptions::default()
    }

    pub fn add(&mut self, opt: ExtractOption) -> &mut Self {
        let flag = match opt {
            ExtractOption::Owner => ffi::ARCHIVE_EXTRACT_OWNER,
            ExtractOption::Permissions => ffi::ARCHIVE_EXTRACT_PERM,
            ExtractOption::Time => ffi::ARCHIVE_EXTRACT_TIME,
            ExtractOption::NoOverwrite => ffi::ARCHIVE_EXTRACT_NO_OVERWRITE,
            ExtractOption::Unlink => ffi::ARCHIVE_EXTRACT_UNLINK,
            ExtractOption::ACL => ffi::ARCHIVE_EXTRACT_ACL,
            ExtractOption::FFlags => ffi::ARCHIVE_EXTRACT_FFLAGS,
            ExtractOption::XAttr => ffi::ARCHIVE_EXTRACT_XATTR,
            ExtractOption::SecureSymlinks => ffi::ARCHIVE_EXTRACT_SECURE_SYMLINKS,
            ExtractOption::SecureNoDotDot => ffi::ARCHIVE_EXTRACT_SECURE_NODOTDOT,
            ExtractOption::NoAutoDir => ffi::ARCHIVE_EXTRACT_NO_AUTODIR,
            ExtractOption::NoOverwriteNewer => ffi::ARCHIVE_EXTRACT_NO_OVERWRITE_NEWER,
            ExtractOption::Sparse => ffi::ARCHIVE_EXTRACT_SPARSE,
            ExtractOption::MacMetadata => ffi::ARCHIVE_EXTRACT_MAC_METADATA,
            ExtractOption::NoHFSCompression => ffi::ARCHIVE_EXTRACT_NO_HFS_COMPRESSION,
            ExtractOption::HFSCompressionForced => ffi::ARCHIVE_EXTRACT_HFS_COMPRESSION_FORCED,
            ExtractOption::SecureNoAbsolutePaths => ffi::ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS,
            ExtractOption::ClearNoChangeFFlags => ffi::ARCHIVE_EXTRACT_CLEAR_NOCHANGE_FFLAGS,
        };
        self.flags |= flag;
        self
    }
}

impl Default for ExtractOptions {
    fn default() -> ExtractOptions {
        ExtractOptions { flags: 0 }
    }
}
