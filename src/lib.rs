//! Fast, efficient, and easy-to-use Python SSH client library.

use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

use pyo3::prelude::*;
use ssh2::Session;

use crate::auth::{Password, PrivateKey};

pub mod auth;

#[pyclass]
pub struct Connection {
    #[allow(dead_code)]
    sess: Session,
}

#[pymethods]
impl Connection {
    // TODO: return PyResult instead of unwrapping.
    #[new]
    #[pyo3(signature = (host, user, password = None, private_key = None, port = 22, timeout = 10)
    )]
    pub fn new(
        host: String,
        user: String,
        password: Option<Password>,
        private_key: Option<PrivateKey>,
        port: u16,
        timeout: u64,
    ) -> Self {
        let addr: SocketAddr = format!("{host}:{port}").parse().unwrap();
        let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(timeout)).unwrap();

        let mut sess = Session::new().unwrap();
        sess.set_tcp_stream(tcp);
        sess.handshake().unwrap();

        if let Some(private_key) = private_key {
            sess.userauth_pubkey_file(
                &user,
                None,
                Path::new(&private_key.key),
                private_key.passphrase.as_deref(),
            )
                .unwrap();
        }

        if let Some(password) = password {
            sess.userauth_password(&user, &password.0).unwrap();
        }

        Self { sess }
    }
}

#[pymodule]
fn russh(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Connection>()?;
    m.add_class::<Password>()?;
    m.add_class::<PrivateKey>()?;

    Ok(())
}
