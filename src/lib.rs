//! Fast, efficient, and easy-to-use Python SSH client library.

use pyo3::prelude::*;

#[pyfunction]
fn sum(a: usize, b: usize) -> usize {
    a + b
}

#[pymodule]
fn russh(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sum, m)?)?;
    
    Ok(())
}
