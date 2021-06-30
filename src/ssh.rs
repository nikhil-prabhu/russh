use crate::constants::*;

use pyo3::prelude::*;
use ssh2::Session;
use std::net::TcpStream;
use std::path::Path;

#[pyclass]
#[derive(Clone)]
/// SSH connection configuration.
pub struct SSHConfig {
	addr: String,
	port: u16,
	user: String,
	auth: String,
}

#[pyclass]
#[derive(Clone)]
/// Represents an SSH connection.
pub struct Conn {
	config: SSHConfig,
	sess: ssh2::Session,
}

#[pymethods]
impl SSHConfig {
	// TODO: Add other auth options (interactive, host-agent, etc.).
	#[new]
	/// Returns an SSH configuration object.
	///
	/// # Arguments:
	///
	/// * `addr` - The address of the host.
	/// * `port` - The SSH port.
	/// * `user` - The remote username.
	/// * `auth` - Either a password or the path to a private key file.
	pub fn new(addr: String, port: Option<u16>, user: String, auth: String) -> Self {
		if let Some(p) = port {
			return Self {
				addr,
				port: p,
				user,
				auth,
			};
		}

		// If no port is specified, we use the default SSH port.
		Self {
			addr,
			port: DEFAULT_SSH_PORT,
			user,
			auth,
		}
	}
}

#[pymethods]
impl Conn {
	// TODO: Improve error handling, rather than just panicking on error.
	#[new]
	/// Establishes an SSH connection and returns the connection object.
	///
	/// # Arguments:
	///
	/// * `addr` - The address (along with port) of the host.
	/// * `user` - The username.
	/// * `auth` - Either a password or the path to a private key file.
	pub fn new(config: SSHConfig) -> Self {
		// We create a TCP stream and connect a session to it.
		let tcp = TcpStream::connect(format!("{}:{}", &config.addr, &config.port)).unwrap();
		let mut sess = Session::new().unwrap();
		sess.set_tcp_stream(tcp);
		sess.handshake().unwrap();

		// We check whether the issued `auth` value is a password or the
		// path to a private key and authenticate the session using
		// the appropriate method.
		let keyfile = Path::new(&config.auth);
		if keyfile.exists() {
			sess.userauth_pubkey_file(&config.user, None, &keyfile, None)
				.unwrap();
		} else {
			sess.userauth_password(&config.user, &config.auth).unwrap();
		}
		drop(keyfile);

		// TODO: Improve authentication verification.
		assert!(sess.authenticated());

		Self { config, sess }
	}
}
