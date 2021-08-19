extern crate libarchive;

use libarchive::archive::{ReadFilter, ReadFormat};
use libarchive::reader;
use libarchive::writer;

use std::env;

fn main() {
  let path = if let Some(_path) = env::args().skip(1).next() {
    _path
  } else {
    println!("No input path provided");
    return
  };

  let mut builder = reader::Builder::new();
  builder.support_format(ReadFormat::All).expect("Add read formats");
  builder.support_filter(ReadFilter::All).expect("Add read filters");

  let mut reader = builder.open_file(path).expect("Opened archive");

  let mut writer = writer::Disk::new();

  writer.write(&mut reader, None).expect("Write out complete contents of archive");
}
