use std::any::Any;
use std::default::Default;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read};
use std::mem;
use std::os::fd::{FromRawFd, IntoRawFd};
use std::path::Path;
use std::ptr;
use std::slice;

use libarchive3_sys::ffi;
use libc::{c_void, ssize_t};

use archive::{Entry, Handle, ReadCompression, ReadFilter, ReadFormat};
use error::{ArchiveError, Result};

const BLOCK_SIZE: usize = 10240;

unsafe extern "C" fn stream_read_callback(
    handle: *mut ffi::Struct_archive,
    data: *mut c_void,
    buf: *mut *const c_void,
) -> ssize_t {
    let pipe: &mut Pipe = &mut *(data as *mut Pipe);
    *buf = pipe.buffer.as_mut_ptr() as *mut c_void;
    match pipe.read_bytes() {
        Ok(size) => size as ssize_t,
        Err(e) => {
            let desc = CString::new(e.to_string()).unwrap();
            ffi::archive_set_error(handle, e.raw_os_error().unwrap_or(0), desc.as_ptr());
            -1
        }
    }
}

/// Trait for reading archives
pub trait Reader: Handle {
    fn entry(&mut self) -> &mut ReaderEntry;

    /// Returns the file offset of the end-of-archive marker
    fn header_position(&self) -> i64 {
        // SAFETY: Casting to *mut because these c functions take T* not const T*. They do not
        // modify the pointer, so this is sound.
        unsafe { ffi::archive_read_header_position(self.handle() as *mut _) }
    }

    /// Returns the next entry, or `None` if there are no more entries.
    fn next_header(&mut self) -> Option<&mut ReaderEntry> {
        // SAFETY: Casting to *mut because these c functions take T* not const T*. They do not
        // modify the pointer, so this is sound.
        let res = unsafe {
            ffi::archive_read_next_header(self.handle() as *mut _, &mut self.entry().handle)
        };
        if res == 0 {
            Some(self.entry())
        } else {
            None
        }
    }

    /// Returns a slice of bytes of the raw data of the block.
    fn read_block(&self) -> Result<Option<&[u8]>> {
        let mut buf = ptr::null();
        let mut size = 0;
        let mut offset = 0;

        // SAFETY: Casting to *mut because these c functions take T* not const T*. They do not
        // modify the pointer, so this is sound.
        match unsafe {
            ffi::archive_read_data_block(self.handle() as *mut _, &mut buf, &mut size, &mut offset)
        } {
            ffi::ARCHIVE_EOF => Ok(None),
            ffi::ARCHIVE_OK => Ok(Some(unsafe {
                slice::from_raw_parts(buf as *const u8, size)
            })),
            _ => Err(ArchiveError::Sys(
                self.err_code(),
                self.err_msg().to_owned(),
            )),
        }
    }
}

/// A reader that reads from a file.
pub struct FileReader {
    handle: *mut ffi::Struct_archive,
    entry: ReaderEntry,
}

/// A reader that reads from a data stream in memory.
pub struct StreamReader {
    handle: *mut ffi::Struct_archive,
    entry: ReaderEntry,
    _pipe: Box<Pipe>,
}

/// A reader that reads from a file descriptor.
pub struct FdReader {
    handle: *mut ffi::Struct_archive,
    entry: ReaderEntry,
    fd: i32,
}

/// A struct that allows configuration of the reader before it is created.
pub struct Builder {
    handle: *mut ffi::Struct_archive,
    consumed: bool,
}

/// An entry in the archive
pub struct ReaderEntry {
    handle: *mut ffi::Struct_archive_entry,
}

struct Pipe {
    reader: Box<dyn Read>,
    buffer: Vec<u8>,
}

impl Pipe {
    fn new<T: Any + Read>(src: T) -> Self {
        Pipe {
            reader: Box::new(src),
            buffer: vec![0; 8192],
        }
    }

    fn read_bytes(&mut self) -> io::Result<usize> {
        self.reader.read(&mut self.buffer[..])
    }
}

impl FileReader {
    /// Open a file with a builder (for configuration) and a file path.
    fn open<P: AsRef<Path>>(mut builder: Builder, file: P) -> Result<Self> {
        builder.check_consumed()?;
        let c_file = CString::new(file.as_ref().to_string_lossy().as_bytes()).unwrap();
        unsafe {
            match ffi::archive_read_open_filename(builder.handle_mut(), c_file.as_ptr(), BLOCK_SIZE)
            {
                ffi::ARCHIVE_OK => {
                    builder.consume();
                    Ok(Self::new(builder.handle_mut()))
                }
                _ => Err(ArchiveError::from(&builder as &dyn Handle)),
            }
        }
    }

    /// Create a new FileReader with an raw pointer to an `archive`.
    ///
    /// # Safety
    /// This raw pointer must own the data it is pointing at, or it may get freed twice.
    unsafe fn new(handle: *mut ffi::Struct_archive) -> Self {
        FileReader {
            handle,
            entry: ReaderEntry::default(),
        }
    }
}

impl Handle for FileReader {
    unsafe fn handle(&self) -> *const ffi::Struct_archive {
        self.handle as *const _
    }

    unsafe fn handle_mut(&mut self) -> *mut ffi::Struct_archive {
        self.handle
    }
}

impl Reader for FileReader {
    fn entry(&mut self) -> &mut ReaderEntry {
        &mut self.entry
    }
}

impl Drop for FileReader {
    fn drop(&mut self) {
        unsafe {
            ffi::archive_read_free(self.handle_mut());
        }
    }
}

impl FdReader {
    /// Open a file with a builder (for configuration) and a file path.
    fn open(mut builder: Builder, file: File) -> Result<Self> {
        builder.check_consumed()?;
        let fd = file.into_raw_fd();
        unsafe {
            match ffi::archive_read_open_fd(builder.handle_mut(), fd, BLOCK_SIZE) {
                ffi::ARCHIVE_OK => {
                    builder.consume();
                    Ok(Self {
                        handle: builder.handle_mut(),
                        entry: ReaderEntry::default(),
                        fd,
                    })
                }
                _ => Err(ArchiveError::from(&builder as &dyn Handle)),
            }
        }
    }
}

impl Handle for FdReader {
    unsafe fn handle(&self) -> *const ffi::Struct_archive {
        self.handle as *const _
    }

    unsafe fn handle_mut(&mut self) -> *mut ffi::Struct_archive {
        self.handle
    }
}

impl Reader for FdReader {
    fn entry(&mut self) -> &mut ReaderEntry {
        &mut self.entry
    }
}

impl Drop for FdReader {
    fn drop(&mut self) {
        unsafe {
            ffi::archive_read_free(self.handle_mut());
            drop(File::from_raw_fd(self.fd));
        }
    }
}

impl StreamReader {
    /// Open a stream (anything that impls `Read`) with a builder. Takes ownership of the stream.
    fn open<T: Any + Read>(mut builder: Builder, src: T) -> Result<Self> {
        let mut pipe = Box::new(Pipe::new(src));
        let pipe_ptr: *mut c_void = &mut *pipe as *mut Pipe as *mut c_void;
        match unsafe {
            ffi::archive_read_open(
                builder.handle_mut(),
                pipe_ptr,
                None,
                Some(stream_read_callback),
                None,
            )
        } {
            ffi::ARCHIVE_OK => {
                let reader = StreamReader {
                    handle: unsafe { builder.handle_mut() },
                    entry: ReaderEntry::default(),
                    _pipe: pipe,
                };
                builder.consume();
                Ok(reader)
            }
            _ => {
                builder.consume();
                Err(ArchiveError::from(&builder as &dyn Handle))
            }
        }
    }
}

impl Handle for StreamReader {
    unsafe fn handle(&self) -> *const ffi::Struct_archive {
        self.handle as *const _
    }

    unsafe fn handle_mut(&mut self) -> *mut ffi::Struct_archive {
        self.handle
    }
}

impl Reader for StreamReader {
    fn entry(&mut self) -> &mut ReaderEntry {
        &mut self.entry
    }
}

impl Drop for StreamReader {
    fn drop(&mut self) {
        unsafe {
            ffi::archive_read_free(self.handle_mut());
        }
    }
}

impl Builder {
    pub fn new() -> Self {
        Builder::default()
    }

    /// Enable support for a given compression method.
    pub fn support_compression(&mut self, compression: ReadCompression) -> Result<()> {
        #[rustfmt::skip]
        let result = match compression {
            ReadCompression::All => unsafe { ffi::archive_read_support_compression_all(self.handle_mut()) },
            ReadCompression::Bzip2 => unsafe { ffi::archive_read_support_compression_bzip2(self.handle_mut()) },
            ReadCompression::Compress => unsafe { ffi::archive_read_support_compression_compress(self.handle_mut()) },
            ReadCompression::Gzip => unsafe { ffi::archive_read_support_compression_gzip(self.handle_mut()) },
            ReadCompression::Lzip => unsafe { ffi::archive_read_support_compression_lzip(self.handle_mut()) },
            ReadCompression::Lzma => unsafe { ffi::archive_read_support_compression_lzma(self.handle_mut()) },
            ReadCompression::None => unsafe { ffi::archive_read_support_compression_none(self.handle_mut()) },
            ReadCompression::Rpm => unsafe { ffi::archive_read_support_compression_rpm(self.handle_mut()) },
            ReadCompression::Uu => unsafe { ffi::archive_read_support_compression_uu(self.handle_mut()) },
            ReadCompression::Xz => unsafe { ffi::archive_read_support_compression_xz(self.handle_mut()) },
            ReadCompression::Program(prog) => {
                let c_prog = CString::new(prog).unwrap();
                unsafe {
                    ffi::archive_read_support_compression_program(
                        self.handle_mut(),
                        c_prog.as_ptr(),
                    )
                }
            }
        };
        match result {
            ffi::ARCHIVE_OK => Ok(()),
            _ => Result::from(self as &dyn Handle),
        }
    }

    /// Enable support for a given filter
    pub fn support_filter(&mut self, filter: ReadFilter) -> Result<()> {
        #[rustfmt::skip]
        let result = match filter {
            ReadFilter::All => unsafe { ffi::archive_read_support_filter_all(self.handle_mut()) },
            ReadFilter::Bzip2 => unsafe { ffi::archive_read_support_filter_bzip2(self.handle_mut()) },
            ReadFilter::Compress => unsafe { ffi::archive_read_support_filter_compress(self.handle_mut()) },
            ReadFilter::Grzip => unsafe { ffi::archive_read_support_filter_grzip(self.handle_mut()) },
            ReadFilter::Gzip => unsafe { ffi::archive_read_support_filter_gzip(self.handle_mut()) },
            ReadFilter::Lrzip => unsafe { ffi::archive_read_support_filter_lrzip(self.handle_mut()) },
            ReadFilter::Lzip => unsafe { ffi::archive_read_support_filter_lzip(self.handle_mut()) },
            ReadFilter::Lzma => unsafe { ffi::archive_read_support_filter_lzma(self.handle_mut()) },
            ReadFilter::Lzop => unsafe { ffi::archive_read_support_filter_lzop(self.handle_mut()) },
            ReadFilter::None => unsafe { ffi::archive_read_support_filter_none(self.handle_mut()) },
            ReadFilter::Rpm => unsafe { ffi::archive_read_support_filter_rpm(self.handle_mut()) },
            ReadFilter::Uu => unsafe { ffi::archive_read_support_filter_uu(self.handle_mut()) },
            ReadFilter::Xz => unsafe { ffi::archive_read_support_filter_xz(self.handle_mut()) },
            ReadFilter::Program(prog) => {
                let c_prog = CString::new(prog).unwrap();
                unsafe {
                    ffi::archive_read_support_filter_program(self.handle_mut(), c_prog.as_ptr())
                }
            }
            ReadFilter::ProgramSignature(prog, cb, size) => {
                let c_prog = CString::new(prog).unwrap();
                unsafe {
                    ffi::archive_read_support_filter_program_signature(
                        self.handle_mut(),
                        c_prog.as_ptr(),
                        mem::transmute(cb),
                        size,
                    )
                }
            }
        };
        match result {
            ffi::ARCHIVE_OK => Ok(()),
            _ => Result::from(self as &dyn Handle),
        }
    }

    /// Enable support for a given format.
    pub fn support_format(&mut self, format: ReadFormat) -> Result<()> {
        // SAFETY: Casting to *mut because these c functions take T* not const T*. They do not
        // modify the pointer, so this is sound.
        #[rustfmt::skip]
        let result = match format {
            ReadFormat::SevenZip => unsafe { ffi::archive_read_support_format_7zip(self.handle_mut()) },
            ReadFormat::All => unsafe { ffi::archive_read_support_format_all(self.handle_mut()) },
            ReadFormat::Ar => unsafe { ffi::archive_read_support_format_ar(self.handle_mut()) },
            ReadFormat::Cab => unsafe { ffi::archive_read_support_format_cab(self.handle_mut()) },
            ReadFormat::Cpio => unsafe { ffi::archive_read_support_format_cpio(self.handle_mut()) },
            ReadFormat::Empty => unsafe { ffi::archive_read_support_format_empty(self.handle_mut()) },
            ReadFormat::Gnutar => unsafe { ffi::archive_read_support_format_gnutar(self.handle_mut()) },
            ReadFormat::Iso9660 => unsafe { ffi::archive_read_support_format_iso9660(self.handle_mut()) },
            ReadFormat::Lha => unsafe { ffi::archive_read_support_format_lha(self.handle_mut()) },
            ReadFormat::Mtree => unsafe { ffi::archive_read_support_format_mtree(self.handle_mut()) },
            ReadFormat::Rar => unsafe { ffi::archive_read_support_format_rar(self.handle_mut()) },
            ReadFormat::Raw => unsafe { ffi::archive_read_support_format_raw(self.handle_mut()) },
            ReadFormat::Tar => unsafe { ffi::archive_read_support_format_tar(self.handle_mut()) },
            ReadFormat::Xar => unsafe { ffi::archive_read_support_format_xar(self.handle_mut()) },
            ReadFormat::Zip => unsafe { ffi::archive_read_support_format_zip(self.handle_mut()) },
        };
        match result {
            ffi::ARCHIVE_OK => Ok(()),
            _ => Result::from(self as &dyn Handle),
        }
    }

    /// Open a file with this builder, consuming it and returning a `FileReader`
    pub fn open_file<T: AsRef<Path>>(self, file: T) -> Result<FileReader> {
        self.check_consumed()?;
        FileReader::open(self, file)
    }

    /// Open a stream with this builder, consuming it and returning a `StreamReader`
    pub fn open_stream<T: Any + Read>(self, src: T) -> Result<StreamReader> {
        self.check_consumed()?;
        StreamReader::open(self, src)
    }

    fn check_consumed(&self) -> Result<()> {
        if self.consumed {
            Err(ArchiveError::Consumed)
        } else {
            Ok(())
        }
    }

    fn consume(&mut self) {
        self.consumed = true;
    }
}

impl Handle for Builder {
    unsafe fn handle(&self) -> *const ffi::Struct_archive {
        self.handle as *const _
    }

    unsafe fn handle_mut(&mut self) -> *mut ffi::Struct_archive {
        self.handle
    }
}

impl Drop for Builder {
    fn drop(&mut self) {
        if !self.consumed {
            unsafe {
                ffi::archive_read_free(self.handle);
            }
        }
    }
}

impl Default for Builder {
    fn default() -> Self {
        unsafe {
            let handle = ffi::archive_read_new();
            if handle.is_null() {
                panic!("Allocation error");
            }
            Builder {
                handle,
                consumed: false,
            }
        }
    }
}

impl ReaderEntry {
    /// Create a new ReaderEntry from a raw pointer to an `archive_entry` struct
    ///
    /// # Safety
    /// The pointer must own the struct it points to, otherwise it may be freed twice
    pub unsafe fn new(handle: *mut ffi::Struct_archive_entry) -> Self {
        ReaderEntry { handle }
    }
}

impl Default for ReaderEntry {
    fn default() -> Self {
        ReaderEntry {
            handle: ptr::null_mut(),
        }
    }
}

impl Entry for ReaderEntry {
    unsafe fn entry(&self) -> *const ffi::Struct_archive_entry {
        self.handle as *const _
    }

    unsafe fn entry_mut(&mut self) -> *mut ffi::Struct_archive_entry {
        self.handle
    }
}
