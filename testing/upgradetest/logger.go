package upgradetest

type Logger interface {
	Logf(format string, args ...interface{})
}
