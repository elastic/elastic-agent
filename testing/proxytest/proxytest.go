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

	// proxiedRequests stores a copy of every request this proxy receives.
	proxiedRequests   []string // []*http.Request
	proxiedRequestsMu sync.Mutex
}

// ProxiedRequests returns a slice with a copy of every request the proxy received.
func (p *Proxy) ProxiedRequests() []string {
	p.proxiedRequestsMu.Lock()
	p.proxiedRequestsMu.Unlock()

	rs := make([]string, len(p.proxiedRequests))
	// rs := make([]*http.Request, len(p.proxiedRequests))
	for _, r := range p.proxiedRequests {
		rs = append(rs, r)
		// rs = append(rs, r.Clone(context.Background()))
	}

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

func New(t *testing.T, optns ...Option) *Proxy {
	t.Helper()

	opts := options{addr: ":0"}
	for _, o := range optns {
		o(&opts)
	}

	l, err := net.Listen("tcp", opts.addr) //nolint:gosec // it's a test
	if err != nil {
		t.Fatalf("NewServer failed to create a net.Listener: %v", err)
	}

	s := Proxy{}

	s.Server = &httptest.Server{
		Listener: l,
		Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			switch {
			case opts.rewriteURL != nil:
				opts.rewriteURL(r.URL)
				break
			case opts.rewriteHost != nil:
				r.URL.Host = opts.rewriteHost(r.URL.Host)
			}

			s.proxiedRequestsMu.Lock()
			s.proxiedRequests = append(s.proxiedRequests,
				fmt.Sprintf("%s - %s %s %s", r.Method, r.URL.Scheme, r.URL.Host, r.URL.String()))
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
