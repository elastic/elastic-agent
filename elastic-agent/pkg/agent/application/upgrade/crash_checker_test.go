// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package upgrade

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/core/logger"
)

var (
	testCheckPeriod = 100 * time.Millisecond
)

func TestChecker(t *testing.T) {
	t.Run("no failure when no change", func(t *testing.T) {
		pider := &testPider{}
		ch, errChan := testableChecker(t, pider)
		ctx, canc := context.WithCancel(context.Background())

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

		canc()
		require.NoError(t, err)
	})

	t.Run("no failure when unfrequent change", func(t *testing.T) {
		pider := &testPider{}
		ch, errChan := testableChecker(t, pider)
		ctx, canc := context.WithCancel(context.Background())

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			wg.Done()
			ch.Run(ctx)
		}()

		wg.Wait()
		for i := 0; i < 2; i++ {
			<-time.After(3 * testCheckPeriod)
			pider.Change(i)
		}
		var err error
		select {
		case err = <-errChan:
		default:
		}

		canc()
		require.NoError(t, err)
	})

	t.Run("no failure when change lower than limit", func(t *testing.T) {
		pider := &testPider{}
		ch, errChan := testableChecker(t, pider)
		ctx, canc := context.WithCancel(context.Background())

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			wg.Done()
			ch.Run(ctx)
		}()

		wg.Wait()
		for i := 0; i < 3; i++ {
			<-time.After(7 * testCheckPeriod)
			pider.Change(i)
		}
		var err error
		select {
		case err = <-errChan:
		default:
		}

		canc()
		require.NoError(t, err)
	})

	t.Run("fails when pid changes frequently", func(t *testing.T) {
		pider := &testPider{}
		ch, errChan := testableChecker(t, pider)
		ctx, canc := context.WithCancel(context.Background())

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

		canc()
		require.Error(t, err)
	})
}

func testableChecker(t *testing.T, pider *testPider) (*CrashChecker, chan error) {
	errChan := make(chan error, 1)
	l, _ := logger.New("", false)
	ch, err := NewCrashChecker(context.Background(), errChan, l)
	require.NoError(t, err)

	ch.checkPeriod = testCheckPeriod
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
