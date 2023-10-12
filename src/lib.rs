//! An SSH library for Python; written in Rust.

use pyo3::prelude::*;

use ssh::*;

mod ssh;

#[pymodule]
fn russh(py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add("SessionException", py.get_type::<SessionException>())?;
    m.add("SFTPException", py.get_type::<SFTPException>())?;

    m.add_class::<PasswordAuth>()?;
    m.add_class::<PrivateKeyAuth>()?;
    m.add_class::<AuthMethods>()?;
    m.add_class::<File>()?;
    m.add_class::<SFTPClient>()?;
    m.add_class::<SSHClient>()?;

    Ok(())
}
