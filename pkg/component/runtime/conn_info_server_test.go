// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
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
)

type mockCommunicator struct {
	ch       chan *proto.CheckinObserved
	connInfo *proto.ConnInfo
}

func newMockCommunicator() *mockCommunicator {
	return &mockCommunicator{
		ch: make(chan *proto.CheckinObserved, 1),
		connInfo: &proto.ConnInfo{
			Addr:       getAddress(),
			ServerName: "endpoint",
			Token:      "some token",
			CaCert:     []byte("some CA cert"),
			PeerCert:   []byte("some cert"),
			PeerKey:    []byte("some key"),
			Services:   []proto.ConnInfoServices{proto.ConnInfoServices_CheckinV2},
		},
	}
}

func (c *mockCommunicator) WriteConnInfo(w io.Writer, services ...client.Service) error {
	infoBytes, err := protobuf.Marshal(c.connInfo)
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

func getAddress() string {
	return fmt.Sprintf("127.0.0.1:%d", testPort)
}

func TestConnInfoNormal(t *testing.T) {
	log := testutils.NewErrorLogger(t)

	comm := newMockCommunicator()

	// Start server
	srv, err := newConnInfoServer(log, comm, testPort)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := srv.stop()
		if err != nil {
			t.Fatal(err)
		}
	}()

	const count = 2 // read connection info a couple of times to make sure the server keeps working for multiple calls

	for i := 0; i < count; i++ {
		// Connect to the server
		conn, err := net.Dial("tcp", getAddress())
		if err != nil {
			t.Fatal(err)
		}

		b, err := io.ReadAll(conn)
		if err != nil {
			t.Fatal(err)
		}

		var connInfo proto.ConnInfo
		err = protobuf.Unmarshal(b, &connInfo)
		if err != nil {
			t.Fatal(err)
		}

		// Check the received result
		diff := cmp.Diff(&connInfo, comm.connInfo, cmpopts.IgnoreUnexported(proto.ConnInfo{}))
		if diff != "" {
			t.Error(diff)
		}
	}
}

func TestConnInfoConnCloseThenAnotherConn(t *testing.T) {
	log := testutils.NewErrorLogger(t)

	comm := newMockCommunicator()

	// Start server
	srv, err := newConnInfoServer(log, comm, testPort)
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
	conn, err := net.Dial("tcp", getAddress())
	if err != nil {
		t.Fatal(err)
	}

	// Close connection
	err = conn.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Connect again after closed
	conn, err = net.Dial("tcp", getAddress())
	if err != nil {
		t.Fatal(err)
	}

	b, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}

	var connInfo proto.ConnInfo
	err = protobuf.Unmarshal(b, &connInfo)
	if err != nil {
		t.Fatal(err)
	}

	// Check the received result
	diff := cmp.Diff(&connInfo, comm.connInfo, cmpopts.IgnoreUnexported(proto.ConnInfo{}))
	if diff != "" {
		t.Error(diff)
	}
}

func TestConnInfoClosed(t *testing.T) {
	log := testutils.NewErrorLogger(t)

	comm := newMockCommunicator()

	// Start server
	srv, err := newConnInfoServer(log, comm, testPort)
	if err != nil {
		t.Fatal(err)
	}

	err = srv.stop()
	if err != nil {
		t.Fatal(err)
	}

	_, err = net.Dial("tcp", getAddress())
	if err == nil {
		t.Fatal("want non-nil err")
	}

	// There is no good way to check on connection refused error cross-platform
	// On windows we get windows.WSAECONNREFUSED on *nix we get syscall.ECONNREFUSED
	// Importing the golang.org/x/sys/windows in here in order to get access to windows.WSAECONNREFUSED
	// causes issue for *nix builds: "imports golang.org/x/sys/windows: build constraints exclude all Go files".
	// In order to avoid creating extra plaform specific files compare just errno for this test.
	wantErrNo := int(syscall.ECONNREFUSED)
	if runtime.GOOS == windows {
		wantErrNo = 10061 // windows.WSAECONNREFUSED
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
	log := testutils.NewErrorLogger(t)

	comm := newMockCommunicator()

	// Start server
	srv, err := newConnInfoServer(log, comm, testPort)
	if err != nil {
		t.Fatal(err)
	}

	err = srv.stop()
	if err != nil {
		t.Fatal(err)
	}

	err = srv.stop()
	if err == nil {
		t.Fatal("want err, got nil ")
	}
}

func TestConnInfoStopTimeout(t *testing.T) {
	log := testutils.NewErrorLogger(t)

	comm := newMockCommunicator()

	// Start server
	srv, err := newConnInfoServer(log, comm, testPort)
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
