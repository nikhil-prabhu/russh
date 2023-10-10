//! An SSH library for Python; written in Rust.

mod ssh;

use pyo3::prelude::*;
use pyo3::exceptions::PyException;

use ssh::*;

pyo3::create_exception!(russh, RusshException, PyException);

#[pymodule]
fn russh(py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add("RusshException", py.get_type::<RusshException>())?;

    m.add_class::<PasswordAuth>()?;
    m.add_class::<PrivateKeyAuth>()?;
    m.add_class::<AuthMethods>()?;
    m.add_class::<SSHClient>()?;

    Ok(())
}
