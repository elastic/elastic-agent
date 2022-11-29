// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitoring

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/elastic/elastic-agent-libs/transport/dialer"
)

type hostData struct {
	transport dialer.Builder // The transport builder to use when creating the connection.

	uri          string // The full URI that should be used in connections.
	sanitizedURI string // A sanitized version of the URI without credentials.

	// Parts of the URI.
	host     string // The host and possibly port.
	user     string // Username
	password string // Password
}

// ParseURL returns hostData object from a raw 'host' value and a series of
// defaults that are added to the URL if not present in the rawHost value.
// Values from the rawHost take precedence over the defaults.
func parseURL(rawHost, scheme, user, pass, path, query string) (hostData, error) {
	u, transport, err := getURL(rawHost, scheme, user, pass, path, query)
	if err != nil {
		return hostData{}, err
	}

	return newHostDataFromURLWithTransport(transport, u), nil
}

// NewHostDataFromURLWithTransport Allow to specify what kind of transport to in conjunction of the
// url, this is useful if you use a combined scheme like "http+unix://" or "http+npipe".
func newHostDataFromURLWithTransport(transport dialer.Builder, u *url.URL) hostData {
	var user, pass string
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}

	host := u.Host
	if strings.HasSuffix(u.Scheme, "unix") || strings.HasSuffix(u.Scheme, "npipe") {
		host = u.Path
	}

	return hostData{
		transport:    transport,
		uri:          u.String(),
		sanitizedURI: redactURLCredentials(u).String(),
		host:         host,
		user:         user,
		password:     pass,
	}
}

// getURL constructs a URL from the rawHost value and adds the provided user,
// password, path, and query params if one was not set in the rawURL value.
func getURL(
	rawURL, scheme, username, password, path, query string,
) (*url.URL, dialer.Builder, error) {

	if parts := strings.SplitN(rawURL, "://", 2); len(parts) != 2 {
		// Add scheme.
		rawURL = fmt.Sprintf("%s://%s", scheme, rawURL)
	}

	var t dialer.Builder

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, t, fmt.Errorf("error parsing URL: %w", err)
	}

	// discover the transport to use to communicate with the host if we have a combined scheme.
	// possible values are mb.TransportTCP, mb.transportUnix or mb.TransportNpipe.
	switch u.Scheme {
	case "http+unix":
		t = dialer.NewUnixDialerBuilder(u.Path)
		u.Path = ""
		u.Scheme = "http" //nolint:goconst // it's not worth making it const, name of http will not change
		u.Host = "unix"
	case "http+npipe":
		p := u.Path
		u.Path = ""
		u.Scheme = "http"
		u.Host = "npipe"

		if p == "" && u.Host != "" {
			p = u.Host
		}

		// cleanup of all possible prefixes
		p = strings.TrimPrefix(p, "/pipe")
		p = strings.TrimPrefix(p, `\\.\pipe`)
		p = strings.TrimPrefix(p, "\\")
		p = strings.TrimPrefix(p, "/")

		segs := strings.SplitAfterN(p, "/", 2)
		if len(segs) == 2 {
			p = strings.TrimSuffix(segs[0], "/")
			u.Path = "/" + segs[1]
		}

		p = `\\.\pipe\` + strings.Replace(p, "/", "\\", -1)
		t = dialer.NewNpipeDialerBuilder(p)
	default:
		t = dialer.NewDefaultDialerBuilder()
	}

	setURLUser(u, username, password)

	if !strings.HasSuffix(u.Scheme, "unix") && !strings.HasSuffix(u.Scheme, "npipe") {
		if u.Host == "" {
			return nil, t, fmt.Errorf("error parsing URL: empty host")
		}

		// Validate the host. The port is optional.
		host, _, err := net.SplitHostPort(u.Host)
		if err != nil {
			if strings.Contains(err.Error(), "missing port") {
				host = u.Host
			} else {
				return nil, t, fmt.Errorf("error parsing URL: %w", err)
			}
		}
		if host == "" {
			return nil, t, fmt.Errorf("error parsing URL: empty host")
		}
	}

	if u.Path == "" && path != "" {
		// The path given in the host config takes precedence over the
		// default path.
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		u.Path = path
	}

	// Adds the query params in the url
	u, err = setQueryParams(u, query)
	return u, t, err
}

// setURLUser set the user credentials in the given URL. If the username or
// password is not set in the URL then the default is used (if provided).
func setURLUser(u *url.URL, defaultUser, defaultPass string) {
	var user, pass string
	var userIsSet, passIsSet bool
	if u.User != nil {
		user = u.User.Username()
		if user != "" {
			userIsSet = true
		}
		pass, passIsSet = u.User.Password()
	}

	if !userIsSet && defaultUser != "" {
		userIsSet = true
		user = defaultUser
	}

	if !passIsSet && defaultPass != "" {
		passIsSet = true
		pass = defaultPass
	}

	if passIsSet {
		u.User = url.UserPassword(user, pass)
	} else if userIsSet {
		u.User = url.User(user)
	}
}

// setQueryParams adds the query params to existing query parameters overwriting any
// keys that already exist.
func setQueryParams(u *url.URL, query string) (*url.URL, error) {
	q := u.Query()
	params, err := url.ParseQuery(query)
	if err != nil {
		return u, err
	}
	for key, values := range params {
		for _, v := range values {
			q.Set(key, v)
		}
	}
	u.RawQuery = q.Encode()
	return u, nil

}

// redactURLCredentials returns the URL as a string with the username and
// password redacted.
func redactURLCredentials(u *url.URL) *url.URL {
	redacted := *u
	redacted.User = nil
	return &redacted
}
