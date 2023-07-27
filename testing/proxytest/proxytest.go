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

	"github.com/google/uuid"
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

	opts options
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
	// logFn if set will be used to log every request.
	logFn   func(format string, a ...any)
	verbose bool
}

// WithAddress will set the address the server will listen on. The format is as
// defined by net.Listen for a tcp connection.
func WithAddress(addr string) Option {
	return func(o *options) {
		o.addr = addr
	}
}

// WithRequestLog sets the proxy to log every request using logFn. It uses name
// as a prefix to the log.
func WithRequestLog(name string, logFn func(format string, a ...any)) Option {
	return func(o *options) {
		o.logFn = func(format string, a ...any) {
			logFn("[proxy-"+name+"] "+format, a...)
		}
	}
}

// WithVerboseLog sets the proxy to log every request verbosely. WithRequestLog
// must be used as well, otherwise WithVerboseLog will not take effect.
func WithVerboseLog() Option {
	return func(o *options) {
		o.verbose = true
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

	if opts.logFn == nil {
		opts.logFn = func(format string, a ...any) {}
	}

	l, err := net.Listen("tcp", opts.addr) //nolint:gosec,nolintlint // it's a test
	if err != nil {
		t.Fatalf("NewServer failed to create a net.Listener: %v", err)
	}

	p := Proxy{opts: opts}

	p.Server = &httptest.Server{
		Listener: l,
		//nolint:gosec,nolintlint // it's a test
		Config: &http.Server{Handler: http.HandlerFunc(func(ww http.ResponseWriter, r *http.Request) {
			w := &statusResponseWriter{w: ww}

			requestID := uuid.New().String()
			opts.logFn("[%s] STARTING - %s %s %s %s\n",
				requestID, r.Method, r.URL, r.Proto, r.RemoteAddr)

			p.ServeHTTP(w, r)

			opts.logFn(fmt.Sprintf("[%s] DONE %d - %s %s %s %s\n",
				requestID, w.statusCode, r.Method, r.URL, r.Proto, r.RemoteAddr))
		})}}
	p.Start()

	u, err := url.Parse(p.URL)
	if err != nil {
		panic(fmt.Sprintf("could parse fleet-server URL: %v", err))
	}

	p.Port = u.Port()
	p.LocalhostURL = "http://localhost:" + p.Port

	opts.logFn("running on %s -> %s", p.URL, p.LocalhostURL)
	return &p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	origURL := r.URL.String()

	switch {
	case p.opts.rewriteURL != nil:
		p.opts.rewriteURL(r.URL)
	case p.opts.rewriteHost != nil:
		r.URL.Host = p.opts.rewriteHost(r.URL.Host)
	}

	if p.opts.verbose {
		p.opts.logFn("original URL: %s, new URL: %s",
			origURL, r.URL.String())
	}

	p.proxiedRequestsMu.Lock()
	p.proxiedRequests = append(p.proxiedRequests,
		fmt.Sprintf("%s - %s %s %s",
			r.Method, r.URL.Scheme, r.URL.Host, r.URL.String()))
	p.proxiedRequestsMu.Unlock()

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
		p.opts.logFn("[ERROR] could not write response body: %v", err)
	}
}

// statusResponseWriter wraps a http.ResponseWriter to expose the status code
// through statusResponseWriter.statusCode
type statusResponseWriter struct {
	w          http.ResponseWriter
	statusCode int
}

func (s *statusResponseWriter) Header() http.Header {
	return s.w.Header()
}

func (s *statusResponseWriter) Write(bs []byte) (int, error) {
	return s.w.Write(bs)
}

func (s *statusResponseWriter) WriteHeader(statusCode int) {
	s.statusCode = statusCode
	s.w.WriteHeader(statusCode)
}

func (s *statusResponseWriter) StatusCode() int {
	return s.statusCode
}
