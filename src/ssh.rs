use pyo3::prelude::*;
use ssh2::Session;
use std::net::TcpStream;
use std::path::Path;

#[pyclass]
/// Represents an SSH connection.
pub struct Conn {
	addr: String,
	user: String,
	auth: String,
	sess: ssh2::Session,
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
	pub fn new(addr: String, user: String, auth: String) -> Self {
		// We create a TCP stream and connect a session to it.
		let tcp = TcpStream::connect(&addr).unwrap();
		let mut sess = Session::new().unwrap();
		sess.set_tcp_stream(tcp);
		sess.handshake().unwrap();

		// We check whether the issued `auth` value is a password or the
		// path to a private key and authenticate the session using
		// the appropriate method.
		let keyfile = Path::new(&auth);
		if keyfile.exists() {
			sess.userauth_pubkey_file(&user, None, &keyfile, None)
				.unwrap();
		} else {
			sess.userauth_password(&user, &auth).unwrap();
		}
		drop(keyfile);

		// TODO: Improve authentication verification.
		assert!(sess.authenticated());

		Self {
			addr,
			user,
			auth,
			sess,
		}
	}
}
