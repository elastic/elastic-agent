// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package runner

import (
	"context"
	"sync"
	"time"
)

type RunnerFunc func(context.Context) error

type Runner struct {
	fn RunnerFunc
	cn context.CancelFunc

	mx   sync.Mutex
	done chan struct{}
	err  error
}

func (r *Runner) Stop() {
	r.mx.Lock()
	if r.cn != nil {
		r.cn()
		r.cn = nil
	}
	r.mx.Unlock()
}

func (r *Runner) Err() error {
	r.mx.Lock()
	err := r.err
	r.mx.Unlock()
	return err
}

func (r *Runner) Done() <-chan struct{} {
	return r.done
}

func (r *Runner) DoneWithTimeout(to time.Duration) <-chan struct{} {
	done := make(chan struct{})

	t := time.NewTimer(to)

	go func() {
		defer t.Stop()

		select {
		case <-r.Done():
		case <-t.C:
			r.setError(context.DeadlineExceeded)
		}
		close(done)
	}()

	return done
}

func Start(ctx context.Context, fn RunnerFunc) *Runner {
	ctx, cn := context.WithCancel(ctx)

	r := &Runner{fn: fn, cn: cn, done: make(chan struct{})}

	go func() {
		err := fn(ctx)
		r.setError(err)
		cn()
		close(r.done)
	}()

	return r
}

func (r *Runner) setError(err error) {
	r.mx.Lock()
	// Only set the error if it was not set before. Capturing the first error.
	if r.err == nil {
		r.err = err
	}
	r.mx.Unlock()
}
