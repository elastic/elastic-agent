package common

// Logger is a simple logging interface used by each runner type.
type Logger interface {
	// Logf logs the message for this runner.
	Logf(format string, args ...any)
}
