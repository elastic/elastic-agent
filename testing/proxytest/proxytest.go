// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package proxytest

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

type Proxy struct {
	*httptest.Server

	// Port is the port Server is listening on.
	Port string

	// LocalhostURL is the server URL as "http://localhost:PORT".
	LocalhostURL string

	// proxiedRequests is a "request log" for every request the proxy receives.
	proxiedRequests   []string
	proxiedRequestsMu sync.Mutex
}

// ProxiedRequests returns a slice with the "request log" with every request the
// proxy received.
func (p *Proxy) ProxiedRequests() []string {
	p.proxiedRequestsMu.Lock()
	defer p.proxiedRequestsMu.Unlock()

	var rs []string
	rs = append(rs, p.proxiedRequests...)
	return rs
}

type Option func(o *options)

type options struct {
	addr        string
	rewriteHost func(string) string
	rewriteURL  func(u *url.URL)
}

// WithAddress will set the address the server will listen on. The format is as
// defined by net.Listen for a tcp connection.
func WithAddress(addr string) Option {
	return func(o *options) {
		o.addr = addr
	}
}

// WithRewrite will replace old by new on the request URL host when forwarding it.
func WithRewrite(old, new string) Option {
	return func(o *options) {
		o.rewriteHost = func(s string) string {
			return strings.Replace(s, old, new, 1)
		}
	}
}

// WithRewriteFn calls f on the request *url.URL before forwarding it.
// It takes precedence over WithRewrite. Use if more control over the rewrite
// is needed.
func WithRewriteFn(f func(u *url.URL)) Option {
	return func(o *options) {
		o.rewriteURL = f
	}
}

// New returns a new Proxy ready for use. Use:
//   - WithAddress to set the proxy's address,
//   - WithRewrite or WithRewriteFn to rewrite the URL before forwarding the request.
func New(t *testing.T, optns ...Option) *Proxy {
	t.Helper()

	opts := options{addr: ":0"}
	for _, o := range optns {
		o(&opts)
	}

	l, err := net.Listen("tcp", opts.addr) //nolint:gosec,nolintlint // it's a test
	if err != nil {
		t.Fatalf("NewServer failed to create a net.Listener: %v", err)
	}

	s := Proxy{}

	s.Server = &httptest.Server{
		Listener: l,
		//nolint:gosec,nolintlint // it's a test
		Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			switch {
			case opts.rewriteURL != nil:
				opts.rewriteURL(r.URL)
			case opts.rewriteHost != nil:
				r.URL.Host = opts.rewriteHost(r.URL.Host)
			}

			s.proxiedRequestsMu.Lock()
			s.proxiedRequests = append(s.proxiedRequests,
				fmt.Sprintf("%s - %s %s %s",
					r.Method, r.URL.Scheme, r.URL.Host, r.URL.String()))
			s.proxiedRequestsMu.Unlock()

			r.RequestURI = ""

			resp, err := http.DefaultClient.Do(r)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				msg := fmt.Sprintf("could not make request: %#v", err.Error())
				log.Print(msg)
				_, _ = fmt.Fprint(w, msg)
				return
			}
			defer resp.Body.Close()

			w.WriteHeader(resp.StatusCode)
			for k, v := range resp.Header {
				w.Header()[k] = v
			}

			if _, err = io.Copy(w, resp.Body); err != nil {
				t.Logf("could not write response body: %v", err)
			}
		})}}
	s.Start()

	u, err := url.Parse(s.URL)
	if err != nil {
		panic(fmt.Sprintf("could parse fleet-server URL: %v", err))
	}

	s.Port = u.Port()
	s.LocalhostURL = "http://localhost:" + s.Port

	return &s
}
