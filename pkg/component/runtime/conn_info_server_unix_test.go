// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package runtime

import (
	"net"
	"net/url"
)

func dialLocal(address string) (net.Conn, error) {
	var u *url.URL
	u, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	return net.Dial("unix", u.Path)
}
