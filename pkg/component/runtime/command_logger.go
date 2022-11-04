package runtime

import "github.com/elastic/elastic-agent/pkg/core/logger"

type commandLogger struct {
	logger *logger.Logger
}

func (r *commandLogger) Write(p []byte) (n int, err error) {
	return
}
