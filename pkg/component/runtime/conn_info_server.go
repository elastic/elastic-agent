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
	"time"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/ipc"
)

const (
	defaultStopTimeout = 15 * time.Second
	windows            = "windows"
)

type connInfoServer struct {
	log         *logger.Logger
	listener    net.Listener
	waitCtx     context.Context
	stopTimeout time.Duration
}

func newConnInfoServer(log *logger.Logger, comm Communicator, address string) (*connInfoServer, error) {
	var (
		listener net.Listener
		err      error
	)

	if ipc.IsLocal(address) {
		listener, err = ipc.CreateListener(log, address)
	} else {
		listener, err = net.Listen("tcp", address)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to start connection credentials listener: %w", err)
	}

	s := &connInfoServer{log: log, listener: listener, stopTimeout: defaultStopTimeout}

	var cn context.CancelFunc
	s.waitCtx, cn = context.WithCancel(context.Background())
	go func() {
		defer cn()
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Errorf("failed accept conn info connection: %v", err)
				break
			}
			log.Debugf("client connected, sending connection info")
			err = comm.WriteStartUpInfo(conn)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					log.Errorf("failed write conn info: %v", err)
				}
			}
			err = conn.Close()
			if err != nil {
				log.Errorf("failed conn info connection close: %v", err)
			}
		}
	}()

	return s, nil
}

func (s *connInfoServer) stop() error {
	// wait service stop with timeout
	ctx, cn := context.WithTimeout(s.waitCtx, s.stopTimeout)
	defer cn()

	err := s.listener.Close()
	if err != nil {
		s.log.Errorf("failed close conn info connection: %v", err)
	}

	<-ctx.Done()
	cerr := ctx.Err()
	if errors.Is(cerr, context.Canceled) {
		cerr = nil
	}

	if errors.Is(cerr, context.DeadlineExceeded) {
		s.log.Errorf("timeout while stopping conn info server: %v", err)
	}
	if err != nil {
		return err
	}
	return cerr
}
