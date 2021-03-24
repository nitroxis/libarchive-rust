use std::any::Any;
use std::default::Default;
use std::ffi::CString;
use std::io::{self, Read};
use std::mem;
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

pub trait Reader: Handle {
    fn entry(&mut self) -> &mut ReaderEntry;

    fn header_position(&self) -> i64 {
        // SAFETY: Casting to *mut because these c functions take T* not const T*. They do not
        // modify the pointer, so they really should.
        unsafe { ffi::archive_read_header_position(self.handle() as *mut _) }
    }

    fn next_header(&mut self) -> Option<&mut ReaderEntry> {
        // SAFETY: Casting to *mut because these c functions take T* not const T*. They do not
        // modify the pointer, so they really should.
        let res = unsafe {
            ffi::archive_read_next_header(self.handle() as *mut _, &mut self.entry().handle)
        };
        if res == 0 {
            Some(self.entry())
        } else {
            None
        }
    }

    fn read_block(&self) -> Result<Option<&[u8]>> {
        let mut buf = ptr::null();
        let mut size = 0;
        let mut offset = 0;

        // SAFETY: Casting to *mut because these c functions take T* not const T*. They do not
        // modify the pointer, so they really should.
        match unsafe {
            ffi::archive_read_data_block(self.handle() as *mut _, &mut buf, &mut size, &mut offset)
        } {
            ffi::ARCHIVE_EOF => Ok(None),
            ffi::ARCHIVE_OK => Ok(Some(unsafe {
                slice::from_raw_parts(buf as *const u8, size)
            })),
            _ => Err(ArchiveError::Sys(self.err_code(), self.err_msg())),
        }
    }
}

pub struct FileReader {
    handle: *mut ffi::Struct_archive,
    entry: ReaderEntry,
}

pub struct StreamReader {
    handle: *mut ffi::Struct_archive,
    entry: ReaderEntry,
    _pipe: Box<Pipe>,
}

pub struct Builder {
    handle: *mut ffi::Struct_archive,
    consumed: bool,
}

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
    pub fn open<T: AsRef<Path>>(mut builder: Builder, file: T) -> Result<Self> {
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

    fn new(handle: *mut ffi::Struct_archive) -> Self {
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

impl StreamReader {
    pub fn open<T: Any + Read>(mut builder: Builder, src: T) -> Result<Self> {
        unsafe {
            let mut pipe = Box::new(Pipe::new(src));
            let pipe_ptr: *mut c_void = &mut *pipe as *mut Pipe as *mut c_void;
            match ffi::archive_read_open(
                builder.handle_mut(),
                pipe_ptr,
                None,
                Some(stream_read_callback),
                None,
            ) {
                ffi::ARCHIVE_OK => {
                    let reader = StreamReader {
                        handle: builder.handle_mut(),
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

    pub fn support_compression(&mut self, compression: ReadCompression) -> Result<()> {
        let result = match compression {
            ReadCompression::All => unsafe {
                ffi::archive_read_support_compression_all(self.handle)
            },
            ReadCompression::Bzip2 => unsafe {
                ffi::archive_read_support_compression_bzip2(self.handle)
            },
            ReadCompression::Compress => unsafe {
                ffi::archive_read_support_compression_compress(self.handle)
            },
            ReadCompression::Gzip => unsafe {
                ffi::archive_read_support_compression_gzip(self.handle)
            },
            ReadCompression::Lzip => unsafe {
                ffi::archive_read_support_compression_lzip(self.handle)
            },
            ReadCompression::Lzma => unsafe {
                ffi::archive_read_support_compression_lzma(self.handle)
            },
            ReadCompression::None => unsafe {
                ffi::archive_read_support_compression_none(self.handle)
            },
            ReadCompression::Program(prog) => {
                let c_prog = CString::new(prog).unwrap();
                unsafe {
                    ffi::archive_read_support_compression_program(self.handle, c_prog.as_ptr())
                }
            }
            ReadCompression::Rpm => unsafe {
                ffi::archive_read_support_compression_rpm(self.handle)
            },
            ReadCompression::Uu => unsafe { ffi::archive_read_support_compression_uu(self.handle) },
            ReadCompression::Xz => unsafe { ffi::archive_read_support_compression_xz(self.handle) },
        };
        match result {
            ffi::ARCHIVE_OK => Ok(()),
            _ => Result::from(self as &dyn Handle),
        }
    }

    pub fn support_filter(&mut self, filter: ReadFilter) -> Result<()> {
        let result = match filter {
            ReadFilter::All => unsafe { ffi::archive_read_support_filter_all(self.handle_mut()) },
            ReadFilter::Bzip2 => unsafe {
                ffi::archive_read_support_filter_bzip2(self.handle_mut())
            },
            ReadFilter::Compress => unsafe {
                ffi::archive_read_support_filter_compress(self.handle_mut())
            },
            ReadFilter::Grzip => unsafe {
                ffi::archive_read_support_filter_grzip(self.handle_mut())
            },
            ReadFilter::Gzip => unsafe { ffi::archive_read_support_filter_gzip(self.handle_mut()) },
            ReadFilter::Lrzip => unsafe {
                ffi::archive_read_support_filter_lrzip(self.handle_mut())
            },
            ReadFilter::Lzip => unsafe { ffi::archive_read_support_filter_lzip(self.handle_mut()) },
            ReadFilter::Lzma => unsafe { ffi::archive_read_support_filter_lzma(self.handle_mut()) },
            ReadFilter::Lzop => unsafe { ffi::archive_read_support_filter_lzop(self.handle_mut()) },
            ReadFilter::None => unsafe { ffi::archive_read_support_filter_none(self.handle_mut()) },
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
            ReadFilter::Rpm => unsafe { ffi::archive_read_support_filter_rpm(self.handle_mut()) },
            ReadFilter::Uu => unsafe { ffi::archive_read_support_filter_uu(self.handle_mut()) },
            ReadFilter::Xz => unsafe { ffi::archive_read_support_filter_xz(self.handle_mut()) },
        };
        match result {
            ffi::ARCHIVE_OK => Ok(()),
            _ => Result::from(self as &dyn Handle),
        }
    }

    pub fn support_format(&self, format: ReadFormat) -> Result<()> {
        // SAFETY: Casting to *mut because these c functions take T* not const T*. They do not
        // modify the pointer, so they really should.
        let result = match format {
            ReadFormat::SevenZip => unsafe {
                ffi::archive_read_support_format_7zip(self.handle() as *mut _)
            },
            ReadFormat::All => unsafe {
                ffi::archive_read_support_format_all(self.handle() as *mut _)
            },
            ReadFormat::Ar => unsafe {
                ffi::archive_read_support_format_ar(self.handle() as *mut _)
            },
            ReadFormat::Cab => unsafe {
                ffi::archive_read_support_format_cab(self.handle() as *mut _)
            },
            ReadFormat::Cpio => unsafe {
                ffi::archive_read_support_format_cpio(self.handle() as *mut _)
            },
            ReadFormat::Empty => unsafe {
                ffi::archive_read_support_format_empty(self.handle() as *mut _)
            },
            ReadFormat::Gnutar => unsafe {
                ffi::archive_read_support_format_gnutar(self.handle() as *mut _)
            },
            ReadFormat::Iso9660 => unsafe {
                ffi::archive_read_support_format_iso9660(self.handle() as *mut _)
            },
            ReadFormat::Lha => unsafe {
                ffi::archive_read_support_format_lha(self.handle() as *mut _)
            },
            ReadFormat::Mtree => unsafe {
                ffi::archive_read_support_format_mtree(self.handle() as *mut _)
            },
            ReadFormat::Rar => unsafe {
                ffi::archive_read_support_format_rar(self.handle() as *mut _)
            },
            ReadFormat::Raw => unsafe {
                ffi::archive_read_support_format_raw(self.handle() as *mut _)
            },
            ReadFormat::Tar => unsafe {
                ffi::archive_read_support_format_tar(self.handle() as *mut _)
            },
            ReadFormat::Xar => unsafe {
                ffi::archive_read_support_format_xar(self.handle() as *mut _)
            },
            ReadFormat::Zip => unsafe {
                ffi::archive_read_support_format_zip(self.handle() as *mut _)
            },
        };
        match result {
            ffi::ARCHIVE_OK => Ok(()),
            _ => Result::from(self as &dyn Handle),
        }
    }

    pub fn open_file<T: AsRef<Path>>(self, file: T) -> Result<FileReader> {
        self.check_consumed()?;
        FileReader::open(self, file)
    }

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
    pub fn new(handle: *mut ffi::Struct_archive_entry) -> Self {
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
