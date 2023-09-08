// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

var (
	testCheckPeriod = 100 * time.Millisecond
)

func TestChecker(t *testing.T) {
	t.Run("no failure when no change", func(t *testing.T) {
		pider := &testPider{pid: 111}
		ch, errChan := testableChecker(t, pider)
		ctx, cancel := context.WithCancel(context.Background())

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			wg.Done()
			ch.Run(ctx)
		}()

		wg.Wait()
		<-time.After(6 * testCheckPeriod)

		var err error
		select {
		case err = <-errChan:
		default:
		}

		cancel()
		require.NoError(t, err)
	})

	t.Run("no failure when unfrequent change", func(t *testing.T) {
		const startingPID = 222
		pider := &testPider{pid: startingPID}
		ch, errChan := testableChecker(t, pider)
		ctx, cancel := context.WithCancel(context.Background())

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			wg.Done()
			ch.Run(ctx)
		}()

		wg.Wait()
		for i := 0; i < 2; i++ {
			<-time.After(3 * testCheckPeriod)
			pider.Change(startingPID + i)
		}
		var err error
		select {
		case err = <-errChan:
		default:
		}

		cancel()
		require.NoError(t, err)
	})

	t.Run("no failure when change lower than limit", func(t *testing.T) {
		const startingPID = 333
		pider := &testPider{pid: startingPID}
		ch, errChan := testableChecker(t, pider)
		ctx, cancel := context.WithCancel(context.Background())

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			wg.Done()
			ch.Run(ctx)
		}()

		wg.Wait()
		for i := 0; i < 3; i++ {
			<-time.After(7 * testCheckPeriod)
			pider.Change(startingPID + i)
		}
		var err error
		select {
		case err = <-errChan:
		default:
		}

		cancel()
		require.NoError(t, err)
	})

	t.Run("fails when pid changes frequently", func(t *testing.T) {
		pider := &testPider{}
		ch, errChan := testableChecker(t, pider)
		ctx, cancel := context.WithCancel(context.Background())

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			wg.Done()
			ch.Run(ctx)
		}()

		wg.Wait()
		for i := 0; i < 12; i++ {
			<-time.After(testCheckPeriod / 2)
			pider.Change(i)
		}
		var err error
		select {
		case err = <-errChan:
		default:
		}

		cancel()
		assert.ErrorContains(t, err, "service restarted '3' times within '0.1' seconds")
	})

	t.Run("fails when pid remains 0", func(t *testing.T) {
		const startingPID = 0
		pider := &testPider{pid: startingPID}
		ch, errChan := testableChecker(t, pider)
		ctx, cancel := context.WithCancel(context.Background())

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			wg.Done()
			ch.Run(ctx)
		}()

		wg.Wait()
		for i := 0; i < 3; i++ {
			<-time.After(testCheckPeriod * 3)
			pider.Change(startingPID) // don't change PID
		}
		var err error
		select {
		case err = <-errChan:
		default:
		}

		cancel()
		assert.ErrorContains(t, err, "service remained crashed (PID = 0) within '0.1' seconds")
	})
}

func testableChecker(t *testing.T, pider *testPider) (*CrashChecker, chan error) {
	errChan := make(chan error, 1)
	l, _ := logger.New("", false)
	ch, err := NewCrashChecker(context.Background(), errChan, l, testCheckPeriod)
	require.NoError(t, err)

	ch.sc.Close()
	ch.sc = pider

	return ch, errChan
}

type testPider struct {
	sync.Mutex
	pid int
}

func (p *testPider) Change(pid int) {
	p.Lock()
	defer p.Unlock()
	p.pid = pid
}

func (p *testPider) PID(ctx context.Context) (int, error) {
	p.Lock()
	defer p.Unlock()
	return p.pid, nil
}

func (p *testPider) Close() {}

func (p *testPider) Name() string { return "testPider" }
