use pyo3::prelude::*;

#[pyclass]
#[derive(Clone)]
pub struct Password(pub String);

#[pyclass]
#[derive(Clone, Default)]
pub struct PrivateKey {
    pub key: String,
    pub passphrase: Option<String>,
}

#[pymethods]
impl Password {
    #[new]
    pub fn new(password: String) -> Self {
        Self(password)
    }
}

#[pymethods]
impl PrivateKey {
    #[new]
    #[pyo3(signature = (key, passphrase = None))]
    pub fn new(key: String, passphrase: Option<String>) -> Self {
        Self { key, passphrase }
    }
}
