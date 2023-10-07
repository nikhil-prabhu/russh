use pyo3::prelude::*;

#[pymodule]
fn russh(_py: Python<'_>, _m: &PyModule) -> PyResult<()> {
    Ok(())
}
