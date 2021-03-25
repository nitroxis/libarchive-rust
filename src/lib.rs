//! # Libarchive-rust
//! 
//! A rust wrapper for [libarchive](https://www.libarchive.org/).
//! 
//! This provides safe and fast implementations of readers and writers of archives, as well as
//! providing public traits, so users can implement their own if their use case demands it.
//! 
//! ## Requirements
//! 
//! This library depends on `libarchive3`. This can be found [here](https://www.libarchive.org/). This
//! is a relatively common library, and can therefore be found in the repos of most linux distros:
//! 
//! ### Debian-based
//! 
//! ```shell
//! sudo apt-get install libarchive13
//! ```
//! 
//! ### Mac OS X
//! 
//! ```shell
//! brew install libarchive
//! ```
//! 
//! ## Usage
//! 
//! Put this in your `Cargo.toml`:
//! 
//! ```toml
//! [dependencies]
//! libarchive = { git = "https://github.com/Sciencentistguy/libarchive-rust" }
//! ```
//! 
//! ## Contributing
//! 
//! Contributions are welcome. Libarchive itself is not very well documented, so I've only
//! implemented what I need. Please feel free to send issues and pull requests.
//! 
//! ---
//! 
//! This library is available under the terms of the GNU LGPL.
//! 
//! This is forked from [fnichol/libarchive-rust](https://github.com/fnichol/libarchive-rust), which is available under the MIT licence.

extern crate libarchive3_sys;
extern crate libc;

/// The main module for interfacing with archives. It contains the `Entry` and `Handle` traits.
pub mod archive;

/// This module contains the `Reader` trait as well as two implementations of it:
///  - `FileReader`, for reading from files.
///  - `StreamReader`, from reading from anything that `impl`s `Read`.
/// It also contains a `Builder` struct that is used to configure libarchive.
pub mod reader;

/// This module contains the `Writer` trait as well as two implementations of it:
///  - `FileWriter`, for writing from files.
///  - `StreamWriter`, from writing from anything that `impl`s `Write`.
/// It also contains a `Builder` struct that is used to configure libarchive.
pub mod writer;

/// This module contains the error handling for the crate, including `ArchiveError`, and the
/// `Result<T, ArchiveError>` type alias.
pub mod error;
