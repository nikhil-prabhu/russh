//! SSH types and methods.

use std::error::Error;
use std::fmt;
use std::fmt::Formatter;
use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use ssh2::Session;

/// Default SSH port.
const DEFAULT_PORT: u16 = 22;
/// Default connection timeout.
const DEFAULT_TIMEOUT: u32 = 30;

// TODO: Make custom exception uniquely identifiable in Python, rather than just being a base `Exception`.
#[pyclass]
#[derive(Debug, PartialEq)]
/// Custom Python exception time for any kind of error.
pub struct RusshException(pub String);

#[pymethods]
impl RusshException {
    #[new]
    /// Creates a new [`RusshException`].
    ///
    /// # Arguments
    ///
    /// * `message` - The error message.
    pub fn __new__(message: String) -> Self {
        Self(message)
    }

    /// Python's `__str__` metaclass.
    ///
    /// Returns a string representation of [`Self`].
    pub fn __str__(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for RusshException {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for RusshException {}

impl From<RusshException> for PyErr {
    /// Creates a [`PyErr`] from a [`RusshException`].
    fn from(error: RusshException) -> Self {
        PyErr::new::<PyException, _>(error.to_string())
    }
}

/// Convenience function to convert a generic error to a [`RusshException`].
///
/// # Arguments
///
/// * `err` - The error.
fn russh_exception_from_err<E: Error>(err: E) -> RusshException {
    RusshException(err.to_string())
}

#[pyclass]
#[derive(Clone)]
/// Represents password based authentication.
pub struct PasswordAuth(pub String);

#[pymethods]
impl PasswordAuth {
    #[new]
    /// Creates a new [`PasswordAuth`].
    ///
    /// # Arguments
    ///
    /// * `password` - The password.
    pub fn __new__(password: String) -> Self {
        Self(password)
    }
}

#[pyclass]
#[derive(Clone)]
/// Represents private-key based authentication.
pub struct PrivateKeyAuth {
    /// The path to the private-key file.
    pub private_key: String,
    /// The passphrase for the private-key file.
    pub passphrase: Option<String>,
}

#[pymethods]
impl PrivateKeyAuth {
    #[new]
    /// Creates a new [`PrivateKeyAuth`].
    ///
    /// # Arguments
    ///
    /// * `private_key` - The path to the private-key file.
    /// * `passphrase` - The password for the private-key file.
    pub fn __new__(private_key: String, passphrase: Option<String>) -> Self {
        Self {
            private_key,
            passphrase,
        }
    }
}

#[pyclass]
#[derive(Clone)]
// TODO: Describe order of priority.
/// Represents supported authentication methods.
pub struct AuthMethods {
    /// Password based authentication method.
    pub password: Option<PasswordAuth>,
    /// Private-key based authentication method.
    pub private_key: Option<PrivateKeyAuth>,
}

#[pymethods]
impl AuthMethods {
    #[new]
    /// Creates a new [`AuthMethods`].
    ///
    /// * `password` - Password based authentication method.
    /// * `private_key` - Private-key based authentication method.
    pub fn __new__(password: Option<PasswordAuth>, private_key: Option<PrivateKeyAuth>) -> Self {
        Self {
            password,
            private_key,
        }
    }
}

#[pyclass]
/// The SSH client.
pub struct SSHClient {
    /// Established SSH session.
    sess: Option<Session>,
}

#[pymethods]
impl SSHClient {
    #[new]
    /// Creates a new [`SSHClient`].
    pub fn __new__() -> Self {
        Self { sess: None }
    }

    /// Establishes an SSH connection and sets the created session on the client.
    ///
    /// # Arguments
    ///
    /// * `host` - The host name or address.
    /// * `username` - The SSH username.
    /// * `auth` - The authentication methods to use.
    /// * `port` The SSH port. Defaults to 22.
    /// * `timeout` - The connection timeout (in seconds). Defaults to 30.
    pub fn connect(
        &mut self,
        host: String,
        username: String,
        auth: AuthMethods,
        port: Option<u16>,
        timeout: Option<u32>,
    ) -> Result<(), RusshException> {
        let port = port.unwrap_or(DEFAULT_PORT);
        let timeout = timeout.unwrap_or(DEFAULT_TIMEOUT);
        let addr: SocketAddr = format!("{host}:{port}").parse().map_err(russh_exception_from_err)?;
        let tcp = TcpStream::connect_timeout(
            &addr,
            Duration::from_secs(timeout as u64),
        ).map_err(russh_exception_from_err)?;

        let mut sess = Session::new().map_err(russh_exception_from_err)?;
        sess.set_timeout(timeout * 1000);
        sess.set_tcp_stream(tcp);
        sess.handshake().map_err(russh_exception_from_err)?;

        if let Some(password) = auth.password {
            sess.userauth_password(&username, &password.0).map_err(russh_exception_from_err)?;
        } else if let Some(private_key) = auth.private_key {
            sess.userauth_pubkey_file(
                &username,
                None,
                Path::new(&private_key.private_key),
                private_key.passphrase.as_deref(),
            ).map_err(russh_exception_from_err)?;
        }

        self.sess = Some(sess);

        Ok(())
    }

    // TODO: Return `stdin`, `stdin` and `stdout` rather than just contents of `stdout`.
    /// Executes a command using the underlying session and returns the output.
    ///
    /// # Arguments
    ///
    /// * `command` - The command to run.
    pub fn exec_command(&self, command: String) -> Result<String, RusshException> {
        let mut buf = String::new();

        if let Some(sess) = &self.sess {
            let mut channel = sess.channel_session().map_err(russh_exception_from_err)?;
            channel.exec(&command).map_err(russh_exception_from_err)?;
            channel.read_to_string(&mut buf).map_err(russh_exception_from_err)?;
        }

        Ok(buf)
    }

    /// Closes the underlying session.
    pub fn close(&mut self) {
        self.sess.take();
    }
}
