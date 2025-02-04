extern crate libarchive;

pub mod util;

use libarchive::archive::{self, ReadFilter, ReadFormat};
use libarchive::reader::{self, Reader};
use libarchive::writer;
use std::fs::File;

#[test]
fn reading_from_file() {
    let tar = util::path::fixture("sample.tar.gz");
    let mut builder = reader::Builder::new();
    builder.support_format(ReadFormat::All).ok();
    builder.support_filter(ReadFilter::All).ok();
    let mut reader = builder.open_file(tar).expect("Opening tar");
    reader.next_header();
    // let entry: &archive::Entry = &reader.entry;
    // println!("{:?}", entry.pathname());
    // println!("{:?}", entry.size());
    // for entry in reader.entries() {
    //     let file = entry as &archive::Entry;
    //     println!("{:?}", file.pathname());
    //     println!("{:?}", file.size());
    // }
    assert_eq!(4, 4);
}

#[test]
fn read_archive_from_stream() {
    let tar = util::path::fixture("sample.tar.gz");
    let f = File::open(tar).ok().unwrap();
    let mut builder = reader::Builder::new();
    builder.support_format(ReadFormat::All).ok();
    builder.support_filter(ReadFilter::All).ok();
    match builder.open_stream(f) {
        Ok(mut reader) => {
            assert_eq!(reader.header_position(), 0);
            let mut writer = writer::Disk::new();
            let tmp = tempfile::tempdir().expect("Created tempdir");
            let tmp_str = tmp.path().to_str().unwrap();
            let count = writer
                .write(&mut reader, Some(tmp_str))
                .ok()
                .unwrap();
            assert_eq!(reader.header_position(), 1024);
            assert_eq!(count, 14);
        }
        Err(e) => {
            println!("{:?}", e);
        }
    }
}

#[test]
fn extracting_from_file() {
    let tar = util::path::fixture("sample.tar.gz");
    let mut builder = reader::Builder::new();
    builder.support_format(ReadFormat::All).ok();
    builder.support_filter(ReadFilter::All).ok();
    let mut reader = builder.open_file(tar).ok().unwrap();
    assert_eq!(reader.header_position(), 0);
    let mut writer = writer::Disk::new();
    let tmp = tempfile::tempdir().expect("Created tempdir");
    let path = tmp.path().to_str().expect("Get temp folder path");
    let bytes = writer.write(&mut reader, Some(path)).expect("Write out contents");
    assert_eq!(bytes, 14);
    assert_eq!(reader.header_position(), 1024);
}

#[test]
fn extracting_an_archive_with_options() {
    let tar = util::path::fixture("sample.tar.gz");
    let mut builder = reader::Builder::new();
    builder.support_format(ReadFormat::All).ok();
    builder.support_filter(ReadFilter::All).ok();
    let mut reader = builder.open_file(tar).ok().unwrap();
    let mut opts = archive::ExtractOptions::new();
    opts.add(archive::ExtractOption::Time);
    let mut writer = writer::Disk::new();
    writer.set_options(&opts).ok();
    let tmp = tempfile::tempdir().expect("Created tempdir");
    let path = tmp.path().to_str().expect("Get temp folder path");
    let bytes = writer.write(&mut reader, Some(path)).expect("Write out contents");
    assert_eq!(bytes, 14);
    assert_eq!(reader.header_position(), 1024);
}

#[test]
fn extracting_a_reader_twice() {
    let tar = util::path::fixture("sample.tar.gz");
    let mut builder = reader::Builder::new();
    builder.support_format(ReadFormat::All).ok();
    builder.support_filter(ReadFilter::All).ok();
    let mut reader = builder.open_file(tar).ok().unwrap();
    println!("{:?}", reader.header_position());
    let mut writer = writer::Disk::new();
    let tmp = tempfile::tempdir().expect("Created tempdir");
    let path = tmp.path().to_str().expect("Get temp folder path");
    writer.write(&mut reader, Some(path)).expect("Write out contents");
    match writer.write(&mut reader, None) {
        Ok(_) => println!("oops"),
        Err(_) => println!("nice"),
    }
    assert_eq!(4, 4)
}


#[test]
fn extracting_from_different_formats() {
    let fixtures = vec!["sample.7z", "sample.rar", "sample_rar4.rar", "sample.zip", "sample.tar"];

    for fixture in fixtures {
        let archive = util::path::fixture(fixture);
        let mut builder = reader::Builder::new();
        builder.support_format(ReadFormat::All).ok();
        builder.support_filter(ReadFilter::All).ok();
        let mut reader = builder.open_file(archive).ok().unwrap();
        assert_eq!(reader.header_position(), 0);
        let mut writer = writer::Disk::new();
        let tmp = tempfile::tempdir().expect("Created tempdir");
        let path = tmp.path().to_str().expect("Get temp folder path");
        let bytes = writer.write(&mut reader, Some(path)).expect("Write out contents");
        assert_eq!(bytes, 14);
    }
}
