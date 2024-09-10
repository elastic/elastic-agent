// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	protobuf "google.golang.org/protobuf/proto"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/testutils"
	"github.com/elastic/elastic-agent/pkg/ipc"
)

type mockCommunicator struct {
	ch          chan *proto.CheckinObserved
	startupInfo *proto.StartUpInfo
}

func newMockCommunicator(address string) *mockCommunicator {
	return &mockCommunicator{
		ch: make(chan *proto.CheckinObserved, 1),
		startupInfo: &proto.StartUpInfo{
			Addr:       address,
			ServerName: "endpoint",
			Token:      "some token",
			CaCert:     []byte("some CA cert"),
			PeerCert:   []byte("some cert"),
			PeerKey:    []byte("some key"),
			Services:   []proto.ConnInfoServices{proto.ConnInfoServices_CheckinV2},
		},
	}
}

func (c *mockCommunicator) WriteStartUpInfo(w io.Writer, services ...client.Service) error {
	infoBytes, err := protobuf.Marshal(c.startupInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal connection information: %w", err)
	}
	_, err = w.Write(infoBytes)
	if err != nil {
		return fmt.Errorf("failed to write connection information: %w", err)
	}

	return nil
}

func (c *mockCommunicator) CheckinExpected(expected *proto.CheckinExpected, observed *proto.CheckinObserved) {
}

func (c *mockCommunicator) ClearPendingCheckinExpected() {
}

func (c *mockCommunicator) CheckinObserved() <-chan *proto.CheckinObserved {
	return c.ch
}

const testPort = 6788

// Test Elastic Agent Connection Info sock
const testSock = ".teaci.sock"

func getAddress(dir string, isLocal bool) string {
	if isLocal {
		u := url.URL{}
		u.Path = "/"

		if runtime.GOOS == "windows" {
			u.Scheme = "npipe"
			return u.JoinPath("/", testSock).String()
		}

		u.Scheme = "unix"
		return u.JoinPath(dir, testSock).String()
	}
	return fmt.Sprintf("127.0.0.1:%d", testPort)
}

func runTests(t *testing.T, fn func(*testing.T, string)) {
	sockdir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockdir)

	tests := []struct {
		name    string
		address string
	}{
		{
			name:    "port",
			address: getAddress("", false),
		},
		{
			name:    "local",
			address: getAddress(sockdir, true),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fn(t, tc.address)
		})
	}
}

func TestConnInfoNormal(t *testing.T) {
	runTests(t, testConnInfoNormal)
}

func dialAddress(address string) (net.Conn, error) {
	// Connect to the server
	if ipc.IsLocal(address) {
		return dialLocal(address)
	}

	return net.Dial("tcp", address)
}

func testConnInfoNormal(t *testing.T, address string) {
	log := testutils.NewErrorLogger(t)

	comm := newMockCommunicator(address)

	// Start server
	srv, err := newConnInfoServer(log, comm, address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {

		err := srv.stop()
		if ipc.IsLocal(address) {
			ipc.CleanupListener(log, address)
		}
		if err != nil {
			t.Fatal(err)
		}
	}()

	const count = 2 // read connection info a couple of times to make sure the server keeps working for multiple calls

	for i := 0; i < count; i++ {
		conn, err := dialAddress(address)
		if err != nil {
			t.Fatal(err)
		}

		b, err := io.ReadAll(conn)
		if err != nil {
			t.Fatal(err)
		}

		var startupInfo proto.StartUpInfo
		err = protobuf.Unmarshal(b, &startupInfo)
		if err != nil {
			t.Fatal(err)
		}

		// Check the received result
		diff := cmp.Diff(&startupInfo, comm.startupInfo, cmpopts.IgnoreUnexported(proto.StartUpInfo{}))
		if diff != "" {
			t.Error(diff)
		}
	}
}

func TestConnInfoConnCloseThenAnotherConn(t *testing.T) {
	runTests(t, testConnInfoConnCloseThenAnotherConn)
}

func testConnInfoConnCloseThenAnotherConn(t *testing.T, address string) {
	log := testutils.NewErrorLogger(t)

	comm := newMockCommunicator("")

	// Start server
	srv, err := newConnInfoServer(log, comm, address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := srv.stop()
		if err != nil {
			t.Fatal(err)
		}
	}()

	// Connect to the server
	conn, err := dialAddress(address)
	if err != nil {
		t.Fatal(err)
	}

	// Close connection
	err = conn.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Connect again after closed
	conn, err = dialAddress(address)
	if err != nil {
		t.Fatal(err)
	}

	b, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}

	var startupInfo proto.StartUpInfo
	err = protobuf.Unmarshal(b, &startupInfo)
	if err != nil {
		t.Fatal(err)
	}

	// Check the received result
	diff := cmp.Diff(&startupInfo, comm.startupInfo, cmpopts.IgnoreUnexported(proto.StartUpInfo{}))
	if diff != "" {
		t.Error(diff)
	}
}

func TestConnInfoClosed(t *testing.T) {
	runTests(t, testConnInfoClosed)
}

func testConnInfoClosed(t *testing.T, address string) {
	log := testutils.NewErrorLogger(t)

	comm := newMockCommunicator("")

	// Start server
	srv, err := newConnInfoServer(log, comm, address)
	if err != nil {
		t.Fatal(err)
	}

	err = srv.stop()
	if err != nil {
		t.Fatal(err)
	}

	_, err = dialAddress(address)
	if err == nil {
		t.Fatal("want non-nil err")
	}

	// There is no good way to check on connection refused error cross-platform
	// On windows we get windows.WSAECONNREFUSED on *nix we get syscall.ECONNREFUSED
	// Importing the golang.org/x/sys/windows in here in order to get access to windows.WSAECONNREFUSED
	// causes issue for *nix builds: "imports golang.org/x/sys/windows: build constraints exclude all Go files".
	// In order to avoid creating extra plaform specific files compare just errno for this test.
	wantErrNo := int(syscall.ECONNREFUSED)
	if ipc.IsLocal(address) {
		if runtime.GOOS == windows {
			wantErrNo = 2 // windows.ERROR_FILE_NOT_FOUND
		} else {
			// For local IPC on *nix the syscall.ENOENT is expected
			wantErrNo = int(syscall.ENOENT)
		}
	} else {
		if runtime.GOOS == windows {
			wantErrNo = 10061 // windows.WSAECONNREFUSED
		}
	}

	var (
		syserr syscall.Errno
		errno  int
	)
	if errors.As(err, &syserr) {
		errno = int(syserr)
		if wantErrNo != errno {
			t.Fatal(err)
		}
	} else {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConnInfoDoubleStop(t *testing.T) {
	runTests(t, testConnInfoDoubleStop)
}

func testConnInfoDoubleStop(t *testing.T, address string) {
	log := testutils.NewErrorLogger(t)

	comm := newMockCommunicator("")

	// Start server
	srv, err := newConnInfoServer(log, comm, address)
	if err != nil {
		t.Fatal(err)
	}

	err = srv.stop()
	if err != nil {
		t.Fatal(err)
	}

	err = srv.stop()
	// Double close on named pipe doesn't cause the error
	if !(ipc.IsLocal(address) && runtime.GOOS == "windows") {
		if err == nil {
			t.Fatal("want err, got nil ")
		}
	}
}

func TestConnInfoStopTimeout(t *testing.T) {
	runTests(t, testConnInfoStopTimeout)
}

func testConnInfoStopTimeout(t *testing.T, address string) {
	log := testutils.NewErrorLogger(t)

	comm := newMockCommunicator("")

	// Start server
	srv, err := newConnInfoServer(log, comm, address)
	if err != nil {
		t.Fatal(err)
	}

	// inject the context for wait that we can control to emulate timeout
	var cn context.CancelFunc
	srv.waitCtx, cn = context.WithCancel(context.Background())
	defer cn()

	srv.stopTimeout = 100 * time.Millisecond

	err = srv.stop()
	// Expected timeout on stop
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}
