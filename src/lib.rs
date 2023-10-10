//! An SSH library for Python; written in Rust.

use pyo3::prelude::*;

use ssh::*;

mod ssh;

#[pymodule]
fn russh(py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add("RusshException", py.get_type::<RusshException>())?;

    m.add_class::<PasswordAuth>()?;
    m.add_class::<PrivateKeyAuth>()?;
    m.add_class::<AuthMethods>()?;
    m.add_class::<SSHClient>()?;

    Ok(())
}
