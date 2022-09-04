// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runtime

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type connInfoServer struct {
	listener net.Listener
	wg       sync.WaitGroup
}

func newConnInfoServer(comm Communicator, port int, log *logger.Logger) (*connInfoServer, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("failed to start connection credentials listener: %w", err)
	}

	s := &connInfoServer{listener: listener}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Errorf("failed accept conn info connection: %v", err)
				break
			}
			err = comm.WriteConnInfo(conn)
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

func (s *connInfoServer) stop() {
	s.listener.Close()
	s.wg.Wait()
}
