// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package fleetcontract

import (
	"errors"
	"net/http"
)

var (
	ErrTooManyRequests    = errors.New("too many requests received (429)")
	ErrConnRefused        = errors.New("connection refused")
	ErrTemporaryServerErr = errors.New("temporary server error, please retry later")
	ErrInvalidToken       = errors.New("invalid enrollment token")
	ErrInvalidAPIKey      = errors.New("invalid api key to authenticate with fleet")
)

// TemporaryServerErrorCodes maps HTTP status codes that indicate a transient
// Fleet Server failure. Clients should retry the request with backoff.
var TemporaryServerErrorCodes = map[int]string{
	http.StatusBadGateway:         "BadGateway",
	http.StatusServiceUnavailable: "ServiceUnavailable",
	http.StatusGatewayTimeout:     "GatewayTimeout",
}
