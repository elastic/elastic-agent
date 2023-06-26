// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package utils

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
)

const (
	SocketMaxLength = 256
	SocketScheme    = "npipe"
)

// SocketURLWithFallback builds a path for a Windows named pipe.
// There are several restrictions on these paths.
// 1. Windows named pipes must be less than 256 characters.
// 2. Windows named pipes are just a filename not a path.
// The ids can often be longer than 256 characters and contin path separators.  So we follow this
// algorithm to get unique paths that are less than 104
// characters.
// 1. take sha256 of id
// 2. base64 encode the first 24 bytes of hash (full 32 can be too long)
// 3. use URLencoding for base64, this is filename safe and is shorter than hex
func SocketURLWithFallback(id, dir string) string {
	hashID := sha256.Sum256([]byte(id))
	filename := base64.URLEncoding.EncodeToString(hashID[:24]) + ".sock"
	u := &url.URL{}
	u.Path = "/"
	u.Scheme = SocketScheme
	dir = "/"

	candidateURL := u.JoinPath(dir, filename)
	// the base64 URLEncoding of 24 bits will be less than 256 characters
	return candidateURL.String()
}
