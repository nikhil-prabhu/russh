use pyo3::prelude::*;

// Modules
mod constants;
mod helpers;
mod ssh;

use ssh::*;

#[pymodule]
/// An SSH library for Python; written in Rust.
fn russh(_: Python, m: &PyModule) -> PyResult<()> {
	m.add_class::<ClientConfig>()?;
	m.add_class::<Client>()?;

	Ok(())
}
