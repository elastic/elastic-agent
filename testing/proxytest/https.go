// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package proxytest

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"

	"github.com/elastic/elastic-agent-libs/testing/certutil"
)

func (p *Proxy) serveHTTPS(w http.ResponseWriter, r *http.Request) {
	log := loggerFromReqCtx(r)
	log.Debug("handling CONNECT")

	clientCon, err := hijack(w)
	if err != nil {
		p.http500Error(clientCon, "cannot handle request", err, log)
		return
	}
	defer clientCon.Close()

	// Hijack successful, w is now useless, let's make sure it isn't used by
	// mistake ;)
	w = nil //nolint:ineffassign,wastedassign // w is now useless, let's make sure it isn't used by mistake ;)
	log.Debug("hijacked request")

	// ==================== CONNECT accepted, let the client know
	_, err = clientCon.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		p.http500Error(clientCon, "failed to send 200-OK after CONNECT", err, log)
		return
	}

	// ==================== TLS handshake
	// client will proceed to perform the TLS handshake with the "target",
	// which we're impersonating.

	// generate a TLS certificate matching the target's host
	cert, err := p.newTLSCert(r.URL)
	if err != nil {
		p.http500Error(clientCon, "failed generating certificate", err, log)
		return
	}

	tlscfg := p.TLS.Clone()
	tlscfg.Certificates = []tls.Certificate{*cert}
	clientTLSConn := tls.Server(clientCon, tlscfg)
	defer clientTLSConn.Close()
	err = clientTLSConn.Handshake()
	if err != nil {
		p.http500Error(clientCon, "failed TLS handshake with client", err, log)
		return
	}

	clientTLSReader := bufio.NewReader(clientTLSConn)

	notEOF := func(r *bufio.Reader) bool {
		_, err = r.Peek(1)
		return !errors.Is(err, io.EOF)
	}
	// ==================== Handle the actual request
	for notEOF(clientTLSReader) {
		// read request from the client sent after the 1s CONNECT request
		req, err := http.ReadRequest(clientTLSReader)
		if err != nil {
			p.http500Error(clientTLSConn, "failed reading client request", err, log)
			return
		}

		// carry over the original remote addr
		req.RemoteAddr = r.RemoteAddr

		// the read request is relative to the host from the original CONNECT
		// request and without scheme. Therefore, set them in the new request.
		req.URL, err = url.Parse("https://" + r.Host + req.URL.String())
		if err != nil {
			p.http500Error(clientTLSConn, "failed reading request URL from client", err, log)
			return
		}
		cleanUpHeaders(req.Header)

		// now the request is ready, it can be altered just as an HTTP request
		// can.
		resp, err := p.processRequest(req)
		if err != nil {
			p.http500Error(clientTLSConn, "failed performing request to target", err, log)
			return
		}

		// Send response from target to client
		// 1st - the status code
		_, err = clientTLSConn.Write([]byte("HTTP/1.1 " + resp.Status + "\r\n"))
		if err != nil {
			p.http500Error(clientTLSConn, "failed writing response status line", err, log)
			return
		}

		// 2nd - the headers
		if err = resp.Header.Write(clientTLSConn); err != nil {
			p.http500Error(clientTLSConn, "failed writing TLS response header", err, log)
			return
		}

		// 3rd - indicates the headers are done and the body will follow
		if _, err = clientTLSConn.Write([]byte("\r\n")); err != nil {
			p.http500Error(clientTLSConn, "failed writing TLS header/body separator", err, log)
			return
		}

		// copy the body else
		_, err = io.CopyBuffer(clientTLSConn, resp.Body, make([]byte, 4096))
		if err != nil {
			p.http500Error(clientTLSConn, "failed writing response body", err, log)
			return
		}

		_ = resp.Body.Close()
	}

	log.Debug("EOF reached, finishing HTTPS handler")
}

func (p *Proxy) newTLSCert(u *url.URL) (*tls.Certificate, error) {
	// generate the certificate key - it needs to be RSA because Elastic Defend
	// do not support EC :/
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("could not create RSA private key: %w", err)
	}
	host := u.Hostname()

	var name string
	var ips []net.IP
	ip := net.ParseIP(host)
	if ip == nil { // host isn't an IP, therefore it must be an DNS
		name = host
	} else {
		ips = append(ips, ip)
	}

	cert, _, err := certutil.GenerateGenericChildCert(
		name,
		ips,
		priv,
		&priv.PublicKey,
		p.ca.capriv,
		p.ca.cacert)
	if err != nil {
		return nil, fmt.Errorf("could not generate TLS certificate for %s: %w",
			host, err)
	}

	return cert, nil
}

func (p *Proxy) http500Error(clientCon net.Conn, msg string, err error, log *slog.Logger) {
	p.httpError(clientCon, http.StatusInternalServerError, msg, err, log)
}

func (p *Proxy) httpError(clientCon net.Conn, status int, msg string, err error, log *slog.Logger) {
	log.Error(msg, "err", err)

	_, err = clientCon.Write(generateHTTPResponse(status, []byte(msg)))
	if err != nil {
		log.Error("failed writing response", "err", err)
	}
}

func hijack(w http.ResponseWriter) (net.Conn, error) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(w, "cannot handle request")
		return nil, errors.New("http.ResponseWriter does not support hijacking")
	}

	clientCon, _, err := hijacker.Hijack()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, err = fmt.Fprint(w, "cannot handle request")

		return nil, fmt.Errorf("could not Hijack HTTPS CONNECT request: %w", err)
	}

	return clientCon, err
}

func cleanUpHeaders(h http.Header) {
	h.Del("Proxy-Connection")
	h.Del("Proxy-Authenticate")
	h.Del("Proxy-Authorization")
	h.Del("Connection")
}

func generateHTTPResponse(statusCode int, body []byte) []byte {
	resp := bytes.Buffer{}
	resp.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n",
		statusCode, http.StatusText(statusCode)))
	resp.WriteString("Content-Type: text/plain\r\n")
	resp.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	resp.WriteString("\r\n")
	if len(body) > 0 {
		resp.Write(body)
	}

	return resp.Bytes()
}
