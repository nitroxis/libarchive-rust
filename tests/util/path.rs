use std::env;
use std::path::PathBuf;

pub fn exe_path() -> PathBuf {
    env::current_exe().unwrap()
}

pub fn test_root() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.join("tests")
}

pub fn fixtures() -> PathBuf {
    test_root().join("fixtures")
}

pub fn fixture(name: &str) -> PathBuf {
    fixtures().join(name)
}
