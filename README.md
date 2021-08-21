# Libarchive-rust

A rust wrapper for [libarchive](https://www.libarchive.org/).

This provides safe and fast implementations of readers and writers of archives, as well as
providing public traits, so users can implement their own if their use case demands it.

## Requirements

This library depends on `libarchive3`. This can be found [here](https://www.libarchive.org/). This
is a relatively common library, and can therefore be found in the repos of most linux distros:

### Debian-based

```shell
sudo apt-get install libarchive13
```

### Mac OS X

```shell
brew install libarchive
```

## Usage

Put this in your `Cargo.toml`:

```toml
[dependencies]
libarchive = { git = "https://github.com/AtlanticAccent/libarchive-rust" }
```

## Contributing

Contributions are welcome. Libarchive itself is not very well documented, so I've only
implemented what I need. Please feel free to send issues and pull requests.

---

This library is available under the terms of the GNU LGPL.

This is forked from [fnichol/libarchive-rust](https://github.com/fnichol/libarchive-rust), which is available under the MIT licence.
