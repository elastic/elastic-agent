// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cpulimit

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/limits"
)

const (
	// retryMinDelay is short so that a failed pass is retried soon. The delay grows up to retryMaxDelay.
	retryMinDelay = 5 * time.Second
	retryMaxDelay = time.Minute
	// recheckInterval is the time between checks of an applied cap. A check fixes a quota changed outside the agent.
	recheckInterval = time.Minute
	// backendCallTimeout limits one backend call.
	backendCallTimeout = 30 * time.Second
	// shutdownRemoveTimeout limits the cleanup when Run stops, so the agent stops quickly.
	shutdownRemoveTimeout = 5 * time.Second
)

// passResult is what one pass found, good or bad. The controller drops it if the requested limit changed during the
// pass, because it belongs to the old limit.
type passResult struct {
	// logicalCPUs is the logical CPU count read in the pass, or 0.
	logicalCPUs int
	// activeQuota and effectiveQuota come from the check of the pass. They are skipped when the cap is off and no quota
	// may be removed, and unknown when no check ran or it failed.
	activeQuota    Quota
	effectiveQuota Quota
	// err is an unexpected failure.
	err error
	// unsupported is set when the host cannot enforce the cap by design.
	unsupported *UnsupportedError
	// fixed is true when the quota was wrong and the check after Apply found it right. reason says what was wrong.
	fixed  bool
	reason string
	// applyErr is the error of an Apply whose quota is right anyway.
	applyErr error
	// removed is true when Remove succeeded.
	removed bool
}

// skippedPassResult is the result of a pass with the cap off and no quota that may be removed.
func skippedPassResult() passResult {
	return passResult{activeQuota: skippedQuota(), effectiveQuota: skippedQuota()}
}

func (r *passResult) setErr(err error) {
	if !errors.As(err, &r.unsupported) {
		r.err = err
	}
}

// Controller keeps the CPU quota matching the latest requested CPU limit.
// With a cap requested, it sets the cap, checks it, and keeps checking and fixing it. It retries failures with a
// growing delay.
// Once it works for a requested cap, the quota in the Agent's own mechanism is its to clear, whatever its value: when
// the cap goes off or Run stops, it calls Remove, which is safe when nothing is held. With the cap off and no quota
// that it may remove, it does not read or change the quota.
// It only reports the effective quota and never uses it to decide anything.
// It runs one backend call at a time.
type Controller struct {
	log     *logger.Logger
	backend Backend
	// wakeCh holds at most one signal. It tells Run that the request was set. Extra signals are dropped, so Set never
	// blocks.
	wakeCh chan struct{}

	mu sync.Mutex
	// mayRemove is true once the controller works for a requested cap, until it has removed its quota. Only Run changes
	// it, while holding mu.
	mayRemove bool

	// req is the latest limit given to Set. Before the first Set it is empty, which means no cap.
	req limits.CPULimit
	// gen changes when Set changes the requested limit. A pass publishes its result only if gen stayed the same.
	gen    uint64
	status controllerStatus
	// retryDelay is the delay before the last retry, or 0 when no failure is being retried.
	retryDelay time.Duration
	// loggedErr is the last failure logged as a warning, or empty after a success or a changed request.
	loggedErr string

	// updatesCh holds the newest Snapshot. Only publishLocked sends on it.
	updatesCh       chan Snapshot
	initializedCh   chan struct{}
	initializedOnce sync.Once
}

// NewController returns a Controller that uses backend for all operating system calls.
func NewController(log *logger.Logger, backend Backend) *Controller {
	return &Controller{
		log:     log,
		backend: backend,
		wakeCh:  make(chan struct{}, 1),
		status: controllerStatus{
			activeQuota:    skippedQuota(),
			effectiveQuota: skippedQuota(),
		},
		updatesCh:     make(chan Snapshot, 1),
		initializedCh: make(chan struct{}),
	}
}

// Set records l as the latest requested CPU limit and starts a new pass, also when l did not change.
// It does not wait for the pass.
func (c *Controller) Set(l limits.CPULimit) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if l != c.req {
		c.gen++
		c.retryDelay = 0
		c.loggedErr = ""
		c.status.requestChanged(l.Enabled() || c.mayRemove)
	}
	c.req = l
	if !l.Enabled() {
		c.markInitialized()
	}
	c.publishLocked()

	select {
	case c.wakeCh <- struct{}{}:
	default:
	}
}

// Snapshot returns the current state of the CPU cap.
func (c *Controller) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status.snapshot(c.req, c.mayRemove)
}

// Updates returns a channel that holds the newest Snapshot. A newer Snapshot replaces an unread one.
func (c *Controller) Updates() <-chan Snapshot {
	return c.updatesCh
}

// Initialized returns a channel that is closed once, when the cap is first off, confirmed, or unsupported. While a
// requested cap cannot be applied it stays open, so the caller must limit its wait.
func (c *Controller) Initialized() <-chan struct{} {
	return c.initializedCh
}

// Run keeps the quota matching the request until ctx is done. Then it tries to remove its quota, if it may
// still remove it.
// Call Run only once. It always returns nil.
func (c *Controller) Run(ctx context.Context) error {
	defer c.cleanupOnStop()

	var timer *time.Timer
	var timerC <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-c.wakeCh:
		case <-timerC:
		}
		if ctx.Err() != nil {
			return nil
		}
		if timer != nil {
			timer.Stop()
			timerC = nil
		}

		if wait := c.runPass(ctx); wait > 0 {
			timer = time.NewTimer(wait)
			timerC = timer.C
		}
	}
}

func isUnsupported(err error) bool {
	var unsupported *UnsupportedError
	return errors.As(err, &unsupported)
}

// runPass runs one pass for the latest request: it applies and checks a requested cap, or removes the quota.
// It returns the time to wait before the next pass, or 0 when only a Set starts the next pass.
func (c *Controller) runPass(ctx context.Context) time.Duration {
	c.mu.Lock()
	req, gen, mayRemove := c.req, c.gen, c.mayRemove
	// This pass handles wakes sent before this point. They must not start another pass.
	select {
	case <-c.wakeCh:
	default:
	}
	c.mu.Unlock()

	// Cap is off
	if !req.Enabled() {
		if !mayRemove {
			// A stale pass may have cleared mayRemove without publishing, so this pass updates the state.
			return c.finishPass(ctx, gen, skippedPassResult())
		}
		return c.removePass(ctx, gen)
	}

	// Once the controller works for a cap, it may remove the quota later.
	c.setMayRemove(true)

	var res passResult
	logicalCPUs, err := c.callLogicalCPUs(ctx)
	if err != nil {
		res.setErr(err)
		return c.finishPass(ctx, gen, res)
	}
	res.logicalCPUs = logicalCPUs
	targetCPUs := req.TargetCPUs(logicalCPUs)
	if !c.isCurrent(ctx, gen) {
		return 0
	}

	ins, err := c.callInspect(ctx)
	res.activeQuota, res.effectiveQuota = ins.Active, ins.Effective
	if err != nil {
		res.setErr(err)
		return c.finishPass(ctx, gen, res)
	}
	mismatch := quotaMismatch(ins.Active, targetCPUs, logicalCPUs)
	if mismatch == nil {
		return c.finishPass(ctx, gen, res)
	}
	if !c.startChange(ctx, gen) {
		return 0
	}

	applyErr := c.callApply(ctx, targetCPUs)
	applyUnsupported := isUnsupported(applyErr)
	if !c.isCurrent(ctx, gen) {
		return 0
	}

	ins, err = c.callInspect(ctx)
	res.activeQuota, res.effectiveQuota = ins.Active, ins.Effective
	switch {
	case applyUnsupported:
		res.setErr(applyErr)
	case isUnsupported(err):
		// The host cannot enforce the cap by design, so a failed Apply is not retried.
		res.setErr(err)
	case err != nil && applyErr == nil:
		res.err = err
	case err != nil:
		res.err = errors.Join(applyErr, err)
	default:
		checkErr := quotaMismatch(ins.Active, targetCPUs, logicalCPUs)
		if checkErr == nil {
			res.fixed, res.reason, res.applyErr = true, mismatch.Error(), applyErr
		} else {
			res.err = errors.Join(applyErr, checkErr)
		}
	}
	return c.finishPass(ctx, gen, res)
}

// removePass runs one pass with the cap off. It removes the controller's quota.
func (c *Controller) removePass(ctx context.Context, gen uint64) time.Duration {
	if !c.startChange(ctx, gen) {
		return 0
	}
	var res passResult
	err := c.callRemove(ctx)
	switch {
	case err == nil:
		c.setMayRemove(false)
		res = skippedPassResult()
		res.removed = true
	case isUnsupported(err):
		// The host cannot enforce the cap by design, so the quota can never be removed.
		c.setMayRemove(false)
		res = skippedPassResult()
	default:
		res.err = err
	}
	return c.finishPass(ctx, gen, res)
}

// callApply calls Backend.Apply with backendCallTimeout.
func (c *Controller) callApply(ctx context.Context, cpus float64) error {
	callCtx, cancel := context.WithTimeout(ctx, backendCallTimeout)
	defer cancel()
	if err := c.backend.Apply(callCtx, cpus); err != nil {
		return fmt.Errorf("failed to change the CPU quota: %w", err)
	}
	return nil
}

// callLogicalCPUs calls Backend.LogicalCPUs with backendCallTimeout.
func (c *Controller) callLogicalCPUs(ctx context.Context) (int, error) {
	callCtx, cancel := context.WithTimeout(ctx, backendCallTimeout)
	defer cancel()
	logicalCPUs, err := c.backend.LogicalCPUs(callCtx)
	if err != nil {
		return 0, fmt.Errorf("failed to read the logical CPU count: %w", err)
	}
	if logicalCPUs < 1 {
		return 0, fmt.Errorf("invalid logical CPU count %d", logicalCPUs)
	}
	return logicalCPUs, nil
}

// callRemove calls Backend.Remove with backendCallTimeout.
func (c *Controller) callRemove(ctx context.Context) error {
	callCtx, cancel := context.WithTimeout(ctx, backendCallTimeout)
	defer cancel()
	if err := c.backend.Remove(callCtx); err != nil {
		return fmt.Errorf("failed to remove the CPU quota: %w", err)
	}
	return nil
}

// callInspect calls Backend.Inspect with backendCallTimeout.
func (c *Controller) callInspect(ctx context.Context) (Inspection, error) {
	callCtx, cancel := context.WithTimeout(ctx, backendCallTimeout)
	defer cancel()
	ins, err := c.backend.Inspect(callCtx)
	if err != nil {
		return Inspection{}, fmt.Errorf("failed to inspect the CPU quota: %w", err)
	}
	if !ins.Active.Kind.Known() {
		return Inspection{}, fmt.Errorf("invalid CPU quota kind %q", ins.Active.Kind)
	}
	if !validCPUs(ins.Active) {
		return Inspection{}, fmt.Errorf("invalid CPU quota %v", ins.Active.CPUs)
	}
	if !ins.Effective.Kind.Known() || !validCPUs(ins.Effective) {
		// The effective quota is only shown, so a bad value does not fail the check.
		ins.Effective = unknownQuota()
	}
	if ins.Active.Kind == QuotaNone {
		ins.Active = Quota{Kind: QuotaNone}
	}
	if ins.Effective.Kind == QuotaNone {
		ins.Effective = Quota{Kind: QuotaNone}
	}
	return ins, nil
}

// validCPUs reports whether a set quota has a finite number of CPUs above 0. A snapshot may be encoded as JSON, which
// fails on NaN and Inf.
func validCPUs(q Quota) bool {
	return q.Kind != QuotaSet || (!math.IsNaN(q.CPUs) && !math.IsInf(q.CPUs, 0) && q.CPUs > 0)
}

// quotaMismatch returns nil when active is a quota of targetCPUs CPUs, and an error that says what is wrong otherwise.
func quotaMismatch(active Quota, targetCPUs float64, logicalCPUs int) error {
	switch {
	case active.Kind != QuotaSet:
		return fmt.Errorf("no CPU quota is set, expected %.2f CPUs", targetCPUs)
	case !withinTolerance(active.CPUs, targetCPUs, logicalCPUs):
		return fmt.Errorf("the CPU quota is %.2f CPUs, expected %.2f CPUs", active.CPUs, targetCPUs)
	default:
		return nil
	}
}

// withinTolerance reports whether cpus is close enough to targetCPUs. The allowed gap covers how an operating system
// rounds a stored quota. An invalid number never matches.
func withinTolerance(cpus, targetCPUs float64, logicalCPUs int) bool {
	return math.Abs(cpus-targetCPUs) <= max(0.01, float64(logicalCPUs)/10000)+1e-9
}

func (c *Controller) isCurrent(ctx context.Context, gen uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return ctx.Err() == nil && gen == c.gen
}

// startChange marks the change of the quota as running and publishes it. It returns false when the pass is stale.
func (c *Controller) startChange(ctx context.Context, gen uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx.Err() != nil || gen != c.gen {
		return false
	}
	c.status.pending = true
	c.publishLocked()
	return true
}

// setMayRemove stores mayRemove. Only Run calls it.
func (c *Controller) setMayRemove(mayRemove bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mayRemove = mayRemove
}

// cleanupOnStop removes the controller's quota, if it may. It runs when Run stops.
func (c *Controller) cleanupOnStop() {
	c.mu.Lock()
	mayRemove := c.mayRemove
	c.mu.Unlock()
	if !mayRemove {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownRemoveTimeout)
	defer cancel()
	if err := c.callRemove(ctx); err != nil && !isUnsupported(err) {
		c.log.Warnw("Failed to remove the CPU quota when stopping", "error.message", err.Error())
	}
}

// finishPass stores res and publishes the snapshot if the pass is still current.
// It returns the time to wait before the next pass, or 0 when only a Set starts the next pass.
func (c *Controller) finishPass(ctx context.Context, gen uint64, res passResult) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx.Err() != nil || gen != c.gen {
		return 0
	}

	c.logOutcome(res)
	c.status.record(res)

	if c.status.err == nil {
		c.markInitialized()
		c.retryDelay, c.loggedErr = 0, ""
	}
	c.publishLocked()

	switch {
	case c.status.err != nil:
		c.retryDelay = min(max(2*c.retryDelay, retryMinDelay), retryMaxDelay)
		return c.retryDelay
	case c.req.Enabled() && c.status.unsupported == nil:
		return recheckInterval
	default:
		return 0
	}
}

// logOutcome logs the result of a pass. It runs before the result is recorded, so c.status is still the previous one.
func (c *Controller) logOutcome(res passResult) {
	switch {
	case res.unsupported != nil:
		if c.status.unsupported == nil || c.status.unsupported.Reason != res.unsupported.Reason {
			c.log.Infow("CPU limit enforcement is not supported on this host", "reason", res.unsupported.Reason)
		}
	case res.err != nil:
		action := "Failed to enforce the CPU limit"
		if !c.req.Enabled() {
			action = "Failed to remove the CPU quota"
		}
		msg := res.err.Error()
		if logged := action + ": " + msg; logged != c.loggedErr {
			c.loggedErr = logged
			c.log.Warnw(action+", will retry", "error.message", msg)
		} else {
			c.log.Debugw(action+" again, will retry", "error.message", msg)
		}
	default:
		if res.removed {
			c.log.Info("Removed the CPU quota of the Agent because the CPU limit is off")
		}
		if res.fixed {
			if res.applyErr != nil {
				c.log.Warnw("The CPU quota is as expected although the change failed", "error.message", res.applyErr.Error())
			}
			c.log.Infow("Set the CPU quota to match the requested CPU limit", "reason", res.reason)
		}
		// With the cap off, the removal message covers a recovery.
		if c.status.err != nil && c.req.Enabled() {
			c.log.Info("CPU limit enforcement recovered")
		}
	}
}

// publishLocked sends the current snapshot on updatesCh. It replaces an unread one. The caller holds mu.
func (c *Controller) publishLocked() {
	select {
	case <-c.updatesCh:
	default:
	}
	c.updatesCh <- c.status.snapshot(c.req, c.mayRemove)
}

// markInitialized closes initializedCh the first time it is called. It is safe with or without mu held.
func (c *Controller) markInitialized() {
	c.initializedOnce.Do(func() { close(c.initializedCh) })
}
