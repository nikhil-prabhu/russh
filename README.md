# russh

![maintenance-status](https://img.shields.io/badge/maintenance-experimental-blue.svg)
[![PyPI version](https://badge.fury.io/py/russh.svg)](https://badge.fury.io/py/russh)
[![Supported Python versions](https://img.shields.io/pypi/pyversions/russh.svg)](https://pypi.python.org/pypi/russh/)
[![PyPI license](https://img.shields.io/pypi/l/ansicolortags.svg)](https://pypi.python.org/pypi/ansicolortags/)
[![PyPI status](https://img.shields.io/pypi/status/ansicolortags.svg)](https://pypi.python.org/pypi/ansicolortags/)

![russh: logo](assets/logo.png)

An SSH library for Python; written in Rust.

## About

`russh` is an easy-to-use SSH library for Python, written in Rust using [PyO3](https://github.com/PyO3/pyo3).

This library aims to be as similar to [paramiko](https://pypi.org/project/paramiko/) as possible (for ease of use and familiarity), while also adding some opiniated features/improvements.
Currently, this library supports the SSHv2 protocol by leveraging `libssh2` (using the [ssh2](https://crates.io/crates/ssh2) crate).

This library does not aim to replace paramiko, or any other Python SSH library. Rather, it's just a proof-of-concept to test the viability of a Python library written in Rust.

**NOTE**: This library is currently a work-in-progress, and should not be used in production scenarios.

## Features

- Supports the SSHv2 protocol.
- Supports Python 3.7 and above.
- Cross-platform (Windows, macOS and GNU/Linux).
- Simple and easy to use.
- Fast and memory-safe, thanks to the underlying Rust core.
- Extensible and well-documented.
- Stubs for all classes/objects/methods contain proper type-annotations.

## Contributing

TODO
