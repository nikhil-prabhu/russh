//! An SSH library for Python; written in Rust.

mod ssh;

use pyo3::prelude::*;

#[pymodule]
fn russh(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<ssh::PasswordAuth>()?;
    m.add_class::<ssh::PrivateKeyAuth>()?;
    m.add_class::<ssh::AuthMethods>()?;
    m.add_class::<ssh::SSHClient>()?;

    Ok(())
}
