use crate::constants::*;
use crate::helpers::get_username;

use pyo3::prelude::*;
use ssh2::Session;
use std::collections::HashMap;
use std::fmt;
use std::net::TcpStream;
use std::path::Path;

#[pyclass]
#[derive(Clone)]
/// Authentication methods.
///
/// # Fields:
///
/// * `password` - A regular password.
/// * `private_key` - An SSH private key file.
pub struct AuthMethod {
	password: Option<String>,
	private_key: Option<String>,
}

#[pymethods]
impl AuthMethod {
	#[new]
	/// Returns an authentication method object.
	///
	/// # Arguments:
	///
	/// * `password` - The remote user's password.
	/// * `private_key` - The path to the SSH private key.
	pub fn new(password: Option<String>, private_key: Option<String>) -> Self {
		Self {
			password,
			private_key,
		}
	}
}

#[pyclass]
#[derive(Clone)]
/// SSH connection client configuration.
///
/// # Fields:
///
/// * `addr` - The address of the host.
/// * `port` - The remote SSH port.
/// * `user` - The remote username.
/// * `auth` - Authentication value.
pub struct ClientConfig {
	addr: String,
	port: u16,
	user: String,
	auth: AuthMethod,
}

impl fmt::Display for ClientConfig {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(
			f,
			"ClientConfig(addr={}, port={}, user={})",
			self.addr, self.port, self.user,
		)
	}
}

#[pyclass]
#[derive(Clone)]
/// Represents an SSH connection client.
///
/// # Fields:
///
/// * `config` - The connection client configuration.
/// * `session` - The SSH session.
pub struct Client {
	config: ClientConfig,
	session: ssh2::Session,
}

impl fmt::Display for Client {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "Client(config={})", self.config)
	}
}

#[pymethods]
impl ClientConfig {
	// TODO: Add other auth options (interactive, host-agent, etc.).
	#[new]
	/// Returns an SSH configuration object.
	///
	/// # Arguments:
	///
	/// * `addr` - The address of the host.
	/// * `port` - The SSH port (22 by default).
	/// * `user` - The remote username (current local username by default).
	/// * `auth` - Either a password or the path to a private key file.
	pub fn new(addr: String, port: Option<u16>, user: Option<String>, auth: AuthMethod) -> Self {
		// We initialize these values with default config values.
		let mut some_user = get_username();
		let mut some_port = DEFAULT_SSH_PORT;

		// If config values were specified, we replace the default values.
		if let Some(u) = user {
			some_user = u;
		}

		if let Some(p) = port {
			some_port = p;
		}

		Self {
			addr,
			port: some_port,
			user: some_user,
			auth,
		}
	}

	/// Returns the client configuration object as a string.
	pub fn to_string(&self) -> PyResult<String> {
		Ok(format!("{}", self))
	}

	// TODO: There may be a better way to do this.
	/// Returns the client configuration object as a dictionary.
	pub fn to_dict(&self) -> PyResult<HashMap<&'static str, String>> {
		let mut conf_map: HashMap<&'static str, String> = HashMap::new();

		conf_map.insert("addr", self.addr.clone());
		conf_map.insert("port", self.port.to_string().clone());
		conf_map.insert("user", self.user.clone());

		Ok(conf_map)
	}
}

#[pymethods]
impl Client {
	// TODO: Improve error handling, rather than just panicking on error.
	#[new]
	/// Establishes an SSH connection and returns the connection object.
	///
	/// # Arguments:
	///
	/// * `config` - The connection client configuration.
	pub fn new(config: ClientConfig) -> Self {
		// We create a TCP stream and connect a session to it.
		let tcp = TcpStream::connect(format!("{}:{}", &config.addr, &config.port)).unwrap();
		let mut session = Session::new().unwrap();
		session.set_tcp_stream(tcp);
		session.handshake().unwrap();

		// Perform authentication based on auth method.
		//
		// Authentication method priorities are as follows (in ascending order):
		//
		// 1. Private key.
		// 2. Password.
		if let Some(pk) = &config.auth.private_key {
			// Private key authentication.
			session
				.userauth_pubkey_file(&config.user, None, Path::new(pk), None)
				.unwrap();
		} else if let Some(pw) = &config.auth.password {
			// Password authentication.
			session.userauth_password(&config.user, pw).unwrap();
		}
		// TODO: Improve authentication verification.
		assert!(session.authenticated());

		Self { config, session }
	}

	/// Returns the client object as a string.
	pub fn to_string(&self) -> PyResult<String> {
		Ok(format!("{}", self))
	}

	// TODO: There may be a better way to do this.
	/// Returns the client object as a dictionary.
	pub fn to_dict(&self) -> PyResult<HashMap<&'static str, HashMap<&'static str, String>>> {
		let mut client_map: HashMap<&'static str, HashMap<&'static str, String>> = HashMap::new();

		client_map.insert("config", self.config.to_dict().unwrap());

		Ok(client_map)
	}
}
