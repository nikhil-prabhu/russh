use std::env;

/// Returns the username of the current local user.
pub fn get_username() -> String {
	// On Windows, we read the username from the %USERNAME% environment variable.
	if cfg!(target_os = "windows") {
		return env::var("USERNAME").unwrap();
	}

	// On all other platforms, we assume the username is held in the $USER
	// environment variable.
	env::var("USER").unwrap()
}
