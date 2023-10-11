"""An SSH library for Python; written in Rust.
"""

from typing import Optional

class RusshException(Exception):
    """Custom exception type for all `russh` errors.
    """

    ...

class PasswordAuth:
    """Represents password based authentication.
    """

    def __init__(self, password: str) -> None:
        """Creates a new password based authentication method.

        Args:
            password (str): The SSH password.
        """

        ...


class PrivateKeyAuth:
    """Represents private-key based authentication.
    """

    def __init__(self, private_key: str, passphrase: Optional[str] = None) -> None:
        """Creates a new private-key based authentication method.

        Args:
            private_key (str): The path to the private-key file.
            passphrase (Optional[str], optional): The passphrase for the private-key file.
                Defaults to `None`.
        """

        ...


class AuthMethods:
    """Represents supported authentication methods.
    """

    def __init__(
            self,
            password: Optional[PasswordAuth] = None,
            private_key: Optional[PrivateKeyAuth] = None,
    ) -> None:
        """Creates a new instance of authentication methods.

        Args:
            password (Optional[PasswordAuth], optional): The password based authentication method.
                Defaults to `None`.
            private_key (Optional[PrivateKeyAuth], optional): The private-key based authentication method.
                Defaults to `None`.
        """

        ...

class ExecOutput:
    """Represents the output produced when running :func:`SSHClient.exec_command`.
    """

    def write_stdin(self, data: str) -> None:
        """Writes the provided data to the `stdin` stream and closes it.

        **NOTE**: Future calls will discard the provided data without doing anything.

        Args:
            data (str): The data to write to the stream.

        Returns:
            None
        """

        ...

    def read_stdout(self) -> str:
        """Reads the contents of the `stdout` stream and consumes it.

        **NOTE**: Future calls will return an empty string.

        Returns:
            The contents of `stdout`.
        """

        ...

    def read_stderr(self) -> str:
        """Reads the contents of the `stderr` stream and consumes it.

        **NOTE**: Future calls will return an empty string.

        Returns:
            The contents of `stderr`.
        """

        ...

    def exit_status(self) -> int:
        """Retrieves the exit status of the command and closes the channel and all streams.

        **NOTE**: Future calls will return 0.

        **NOTE**: Future reads of the `stdout` or `stderr` streams will return empty strings.

        Returns:
            The exit status.
        """

        ...

    def close(self) -> None:
        """Consumes all streams and closes the underlying channel if it exists and is active.

        If there is no active channel, then this function does nothing.

        Returns:
            None
        """

        ...


class SSHClient:
    """The SSH client.
    """

    def __init__(self) -> None:
        """Creates a new SSH client.
        """

        ...

    def connect(
            self,
            host: str,
            username: str,
            auth: AuthMethods,
            port: int = 22,
            timeout: int = 30,
    ) -> None:
        """Establishes an SSH connection and sets the created session on the client.

        Args:
            host (str): The host name or address.
            username (str): The SSH username.
            auth (str): The authentication methods to use.
            port (int, optional): The SSH port. Defaults to 22.
            timeout (int, optional): The connection timeout (in seconds). Defaults to 30.

        Returns:
            None
        """

        ...

    def exec_command(self, command: str) -> ExecOutput:
        """Executes a command using the established session and returns the output.

        Args:
            command (str): The command to run.

        Returns:
            The command's output.
        """

        ...

    def close(self):
        """Closes the underlying session.

        Returns:
            None
        """

        ...
