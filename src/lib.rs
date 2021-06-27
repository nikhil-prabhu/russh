use pyo3::prelude::*;

// Modules
mod ssh;

use ssh::*;

#[pymodule]
/// An SSH library for Python; written in Rust.
fn russh(_: Python, m: &PyModule) -> PyResult<()> {
	m.add_class::<Conn>()?;

	Ok(())
}
