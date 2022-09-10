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
	"syscall"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/testutils"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	protobuf "google.golang.org/protobuf/proto"
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

func (c *mockCommunicator) CheckinExpected(expected *proto.CheckinExpected) {
}

func (c *mockCommunicator) CheckinObserved() <-chan *proto.CheckinObserved {
	return c.ch
}

func (c *mockCommunicator) sendCheckin(checkin *proto.CheckinObserved) {
	c.ch <- checkin
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
	defer srv.stop()

	const count = 2 // read connection info a couple of time to make sure the server keeps working

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
	defer srv.stop()

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
	srv.stop()

	_, err = net.Dial("tcp", getAddress())

	if !errors.Is(err, syscall.ECONNREFUSED) {
		if err != nil {
			t.Fatal(err)
		}
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
	srv.stop()
	srv.stop()
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
