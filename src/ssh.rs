//! SSH types and methods.

use std::error::Error;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use ssh2::{Channel, Session, Sftp, Stream};

/// Default SSH port.
const DEFAULT_PORT: u16 = 22;
/// Default connection timeout.
const DEFAULT_TIMEOUT: u32 = 30;

// Custom Python exception type.
pyo3::create_exception!(russh, RusshException, PyException);

/// Convenience function to convert a generic error to a [`RusshException`].
///
/// # Arguments
///
/// * `err` - The error.
fn russh_exception_from_err<E: Error>(err: E) -> PyErr {
    RusshException::new_err(err.to_string())
}

#[pyclass]
#[derive(Clone)]
/// Represents password-based authentication.
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
/// Represents private-key-based authentication.
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
// TODO: Describe the order of priority.
/// Represents supported authentication methods.
pub struct AuthMethods {
    /// Password-based authentication method.
    pub password: Option<PasswordAuth>,
    /// Private-key-based authentication method.
    pub private_key: Option<PrivateKeyAuth>,
}

#[pymethods]
impl AuthMethods {
    #[new]
    /// Creates a new [`AuthMethods`].
    ///
    /// * `password` - Password-based authentication method.
    /// * `private_key` - Private-key-based authentication method.
    pub fn __new__(password: Option<PasswordAuth>, private_key: Option<PrivateKeyAuth>) -> Self {
        Self {
            password,
            private_key,
        }
    }
}

#[pyclass]
/// Represents the output produced when running [`SSHClient::exec_command`].
pub struct ExecOutput {
    channel: Option<Channel>,
    /// The `stdin` stream.
    stdin: Option<Stream>,
    /// The `stdout` stream's contents.
    stdout: Option<Stream>,
    /// The `stderr` stream's contents.
    stderr: Option<Stream>,
}

#[pymethods]
impl ExecOutput {
    /// Writes the provided data to the `stdin` stream and closes it.
    ///
    /// **NOTE**: Future calls will discard the provided data without doing anything.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to write to the stream.
    pub fn write_stdin(&mut self, data: String) -> PyResult<()> {
        if let Some(mut stdin) = self.stdin.take() {
            if let Some(channel) = self.channel.as_mut() {
                stdin
                    .write_all(data.as_bytes())
                    .map_err(russh_exception_from_err)?;
                stdin.flush().map_err(russh_exception_from_err)?;

                channel.send_eof().map_err(russh_exception_from_err)?;
            }
        }

        Ok(())
    }

    /// Reads the contents of the `stdout` stream and consumes it.
    ///
    /// **NOTE**: Future calls will return an empty string.
    fn read_stdout(&mut self) -> PyResult<String> {
        let mut buf = String::new();

        if let Some(mut stdout) = self.stdout.take() {
            stdout
                .read_to_string(&mut buf)
                .map_err(russh_exception_from_err)?;
        }

        Ok(buf)
    }

    /// Reads the contents of the `stderr` stream and consumes it.
    ///
    /// **NOTE**: Future calls will return an empty string.
    fn read_stderr(&mut self) -> PyResult<String> {
        let mut buf = String::new();

        if let Some(mut stderr) = self.stderr.take() {
            stderr
                .read_to_string(&mut buf)
                .map_err(russh_exception_from_err)?;
        }

        Ok(buf)
    }

    /// Retrieves the exit status of the command and closes the channel and all streams.
    ///
    /// **NOTE**: Future calls will return 0.
    ///
    /// **NOTE**: Future reads of the `stdout` or `stderr` streams will return empty strings.
    fn exit_status(&mut self) -> PyResult<i32> {
        let mut exit_status = 0;

        if let Some(mut chan) = self.channel.take() {
            let mut stdout = String::new();
            let mut stderr = String::new();

            chan.read_to_string(&mut stdout)
                .map_err(russh_exception_from_err)?;
            chan.stderr()
                .read_to_string(&mut stderr)
                .map_err(russh_exception_from_err)?;

            chan.wait_close().map_err(russh_exception_from_err)?;
            exit_status = chan.exit_status().map_err(russh_exception_from_err)?;
        }

        Ok(exit_status)
    }

    /// Consumes all streams and closes the underlying channel if it exists and is active.
    ///
    /// If there is no active channel, then this function does nothing.
    fn close(&mut self) -> PyResult<()> {
        self.stdin.take();
        self.stdout.take();
        self.stderr.take();

        if let Some(mut channel) = self.channel.take() {
            channel.close().map_err(russh_exception_from_err)?;
        }

        Ok(())
    }
}

/// Convenience function that concatenates a base and a child path into a [`PathBuf`].
///
/// If the base is `None`, the child path is returned as a [`PathBuf`].
///
/// # Arguments
///
/// * `base` - Optional base path.
/// * `path` - The child path.
fn path_from_string(base: Option<String>, path: String) -> PathBuf {
    if let Some(base) = base {
        let mut base_path = PathBuf::new();
        base_path.push(base);
        base_path.push(path);

        return base_path;
    }

    Path::new(&path).to_path_buf()
}

#[pyclass]
/// A file on a remote server.
pub struct File(pub ssh2::File);

#[pymethods]
impl File {
    /// Reads and returns the contents of the file.
    pub fn read(&mut self) -> PyResult<String> {
        let mut buf = String::new();
        self.0
            .read_to_string(&mut buf)
            .map_err(russh_exception_from_err)?;

        Ok(buf)
    }

    /// Writes the specified data to the file.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to write to the file.
    pub fn write(&mut self, data: String) -> PyResult<()> {
        self.0
            .write_all(data.as_bytes())
            .map_err(russh_exception_from_err)
    }
}
#[pyclass]
/// The SFTP client.
pub struct SFTPClient {
    /// Underlying SFTP client.
    client: Option<Sftp>,
    /// Current working directory.
    cwd: Option<String>,
}

#[pymethods]
impl SFTPClient {
    /// Changes the current working directory to the specified directory.
    ///
    /// If the specified directory is `None`, then the current working directory is unset.
    ///
    /// Once the current working directory is set, all SFTP operations will be relative to this path.
    ///
    /// **NOTE**: SFTP does not have a concept of a "current working directory", and so, this function
    /// tries to emulate it. Currently, only **absolute** paths are supported. This *MAY* change in the
    /// future, but is not guaranteed.
    ///
    /// # Arguments
    ///
    /// * `dir` - The directory to change to.
    pub fn chdir(&mut self, dir: Option<String>) -> PyResult<()> {
        if let Some(client) = self.client.as_mut() {
            if let Some(path) = &dir {
                let path = Path::new(&path);

                if let Err(_) = client.opendir(path) {
                    return Err(RusshException::new_err(format!(
                        "Path {} does not exist on server",
                        path.display()
                    )));
                }
            }

            self.cwd = dir;
        } else {
            return Err(RusshException::new_err("SFTP session not open".to_string()));
        }

        Ok(())
    }

    /// Returns the current working directory.
    pub fn getcwd(&self) -> Option<String> {
        self.cwd.clone()
    }

    /// Opens a file on the remote server.
    ///
    /// The opened file is both readable and writable.
    ///
    /// # Arguments
    ///
    /// * `filename` - The name of the file (if file is in `cwd`) OR the path to the file.
    pub fn open(&mut self, filename: String) -> PyResult<File> {
        if let Some(client) = self.client.as_mut() {
            let path = path_from_string(self.cwd.clone(), filename);
            return Ok(File(client.open(&path).map_err(russh_exception_from_err)?));
        }

        Err(RusshException::new_err("SFTP session not open".to_string()))
    }

    /// Checks if the SFTP session is closed.
    pub fn is_closed(&self) -> bool {
        self.client.is_none()
    }

    /// Closes the SFTP session.
    pub fn close(&mut self) {
        self.client.take();
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
    /// * `timeout` - The timeout for the TCP connection (in seconds). Defaults to 30.
    pub fn connect(
        &mut self,
        host: String,
        username: String,
        auth: AuthMethods,
        port: Option<u16>,
        timeout: Option<u32>,
    ) -> PyResult<()> {
        let port = port.unwrap_or(DEFAULT_PORT);
        let timeout = timeout.unwrap_or(DEFAULT_TIMEOUT);
        let addr: SocketAddr = format!("{host}:{port}")
            .parse()
            .map_err(russh_exception_from_err)?;
        let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(timeout as u64))
            .map_err(russh_exception_from_err)?;

        let mut sess = Session::new().map_err(russh_exception_from_err)?;
        sess.set_tcp_stream(tcp);
        sess.handshake().map_err(russh_exception_from_err)?;

        if let Some(password) = auth.password {
            sess.userauth_password(&username, &password.0)
                .map_err(russh_exception_from_err)?;
        } else if let Some(private_key) = auth.private_key {
            sess.userauth_pubkey_file(
                &username,
                None,
                Path::new(&private_key.private_key),
                private_key.passphrase.as_deref(),
            )
            .map_err(russh_exception_from_err)?;
        }

        self.sess = Some(sess);

        Ok(())
    }

    /// Opens an SFTP session using the SSH session.
    ///
    /// Fails if there is no active SSH session (if [`SSHClient::connect`] was not called).
    pub fn open_sftp(&self) -> PyResult<SFTPClient> {
        if let Some(sess) = &self.sess {
            let client = Some(sess.sftp().map_err(russh_exception_from_err)?);
            return Ok(SFTPClient { client, cwd: None });
        }

        Err(RusshException::new_err("No active SSH session".to_string()))
    }

    /// Executes a command using the underlying session and returns the output.
    ///
    /// # Arguments
    ///
    /// * `command` - The command to run.
    pub fn exec_command(&self, command: String) -> PyResult<ExecOutput> {
        let mut stdin = None;
        let mut stdout = None;
        let mut stderr = None;
        let mut channel = None;

        if let Some(sess) = &self.sess {
            let mut chan = sess.channel_session().map_err(russh_exception_from_err)?;
            chan.exec(&command).map_err(russh_exception_from_err)?;

            stdin = Some(chan.stream(0));
            stdout = Some(chan.stream(0));
            stderr = Some(chan.stderr());
            channel = Some(chan);
        }

        Ok(ExecOutput {
            channel,
            stdin,
            stdout,
            stderr,
        })
    }

    /// Closes the underlying session.
    pub fn close(&mut self) {
        self.sess.take();
    }
}
