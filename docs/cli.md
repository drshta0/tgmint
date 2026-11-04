# CLI reference

`tgmint` installs a command with the same name. `python -m tgmint` works too.
The CLI uses only the standard library, and every command accepts `--json`,
so non-Python tools (GramJS, MadelineProto, shell scripts) can use it.

Secrets never go on the command line. Passphrases and tdata passcodes are read
from an environment variable you name (`--passphrase-env VAR`,
`--passcode-env VAR`) or from an interactive prompt.

This page is generated from the CLI's own `--help` output each time the docs
are built, so it always matches the installed version.

<!-- tgmint-cli-reference -->
