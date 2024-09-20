package ssh

type fileContentsOpts struct {
	command string
}

// FileContentsOpt provides an option to modify how fetching files from the remote host work.
type FileContentsOpt func(opts *fileContentsOpts)

// WithContentFetchCommand changes the command to use for fetching the file contents.
func WithContentFetchCommand(command string) FileContentsOpt {
	return func(opts *fileContentsOpts) {
		opts.command = command
	}
}
