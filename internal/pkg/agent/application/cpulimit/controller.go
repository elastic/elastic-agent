// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cpulimit

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sync"
	"time"

	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/limits"
)

const (
	// retryMinDelay is short so that a failed check is retried soon and the cap is applied as early as the host allows.
	// The delay doubles after each failure in a row, up to retryMaxDelay.
	retryMinDelay = 5 * time.Second
	retryMaxDelay = time.Minute
	// recheckInterval is the time between checks while a cap is applied, so a quota changed outside the agent is
	// corrected.
	recheckInterval = time.Minute
	callTimeout     = 30 * time.Second
	// shutdownRemoveTimeout limits the removal of the agent quota when Run stops, so the agent stops quickly.
	shutdownRemoveTimeout = 5 * time.Second
)

// Controller keeps the CPU quota in the operating system in line with the latest requested CPU limit.
// It runs one backend call at a time. A Set that changes the value does not stop a running call: the call ends or
// times out, its result is dropped, and the next pass corrects the quota. A Set with the same value lets the running
// pass finish and runs one more check after it.
// While a cap is requested and the last check passed, it checks again every minute and corrects the quota if needed.
// Failures are retried after 5 seconds, and the delay doubles after each failure in a row, up to one minute.
// A Set with a new value is a new request: it clears an old failure and shows StatePending while its first pass runs.
// A retry of a failed request, or a Set with the same value, keeps StateDegraded until a pass succeeds.
// Every Set, and the start of a correction or a removal, publishes a snapshot, also when it is the same as the last one.
// At the end of a pass, a snapshot is published only when it changed.
// When the cap goes off, the controller removes the quota it owns, best effort: it first checks the quota and removes
// it only when the check does not show that someone else changed it. When someone else changed or removed the quota,
// the controller forgets it and changes nothing. A failed removal is retried like a failed check, until it works, the
// controller forgets the quota, or a new Set arrives. The first removal attempt shows StatePending, and a failed removal
// shows StateDegraded while it is retried. With the cap off and no owned quota, the controller does not read or change
// the quota, so a quota set by anyone else, or left by an earlier run, stays as it is.
// Known limit: an Apply that timed out can still take effect after a removal check found no quota and gave up. That
// quota then stays until a later run with the cap on finds it.
// The effective quota is only shown. It never changes the state, the retries or what the controller writes, so a lower
// limit on a parent does not make the controller write the quota again.
type Controller struct {
	log     *logger.Logger
	backend Backend
	wake    chan struct{}
	updates chan Snapshot
	ready   chan struct{}

	mu sync.Mutex
	// owned is true when this controller called Apply, or when a cap-on check found a service quota that already
	// matched the cap and adopted it. A failed Apply counts too, because it may have written the quota, but an
	// unsupported one does not; the check after it can still adopt the quota. The controller removes an owned quota
	// when the cap goes off or when Run stops.
	// The backend cannot tell a quota set by the agent from one set in another way, so an adopted quota may not be the
	// agent's own. Remove then changes nothing.
	// Only Run writes it, while holding mu, so Run may read it without mu.
	owned bool
	// ownedQuota is the service quota as last seen by a check that found the requested cap in place. Each Apply makes it
	// unknown until a check after it passes, because the write may still take effect later. An unsupported Apply does
	// not change it. Only Run uses it.
	ownedQuota Quota

	req limits.CPULimit
	// gen grows when Set changes the value. A pass publishes its result only if gen did not change while it ran.
	gen uint64
	// changing is true while a requested cap is not checked yet or while a pass corrects the quota.
	changing    bool
	failed      bool
	unsupported bool
	reason      string
	err         error
	quota       Quota
	// effective is the last effective quota. It is only shown.
	effective Quota
	// cpus is the last logical CPU count, or 0 if it was never read.
	cpus        int
	readyClosed bool
	// retryDelay is the delay before the last retry, or 0 after a success or a change of the requested value.
	retryDelay time.Duration
	// loggedErr is the action and error text of the last failure logged at Warn level. It is empty after a success.
	loggedErr string
	// published is the last snapshot sent to updates.
	published Snapshot
}

// NewController returns a Controller that uses backend for all operating system calls.
func NewController(log *logger.Logger, backend Backend) *Controller {
	return &Controller{
		log:     log,
		backend: backend,
		wake:    make(chan struct{}, 1),
		updates: make(chan Snapshot, 1),
		ready:   make(chan struct{}),
	}
}

// Set records l as the latest accepted CPU limit. With the cap on, it starts a new check, also when l did not change.
// With the cap off, it stops the checks for an earlier cap and starts the removal of the quota this controller owns, if
// any. It returns without waiting for the check or the removal.
func (c *Controller) Set(l limits.CPULimit) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if l != c.req {
		c.gen++
		c.changing = l.Enabled() || c.owned
		// The old result belongs to the old value.
		c.failed, c.err, c.unsupported, c.reason = false, nil, false, ""
		c.retryDelay = 0
	}
	c.req = l
	if !l.Enabled() {
		if !c.owned {
			// With the cap off, the quotas are shown only while an owned quota is being removed.
			c.quota, c.effective = Quota{}, Quota{}
		}
		c.closeReadyLocked()
	}
	c.publishLocked()

	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// Snapshot returns the current state of the CPU cap.
func (c *Controller) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.snapshotLocked()
}

// Updates returns a channel that holds the newest Snapshot. A newer Snapshot replaces an unread one.
func (c *Controller) Updates() <-chan Snapshot {
	return c.updates
}

// Ready returns a channel that is closed the first time the cap is off, verified or unsupported.
// A Set with the cap off closes it at once.
// It stays closed after that.
func (c *Controller) Ready() <-chan struct{} {
	return c.ready
}

// Run reconciles the quota until ctx is done. While the cap is off, it only removes the quota this controller owns.
// Call Run only once.
// When ctx is done, Run removes the quota this controller still owns, so that none is left after the agent stops.
// This is best effort and takes at most 5 seconds. A failure is only logged. A crash cannot clean up, so the quota
// stays until a later run with the cap on finds it and keeps or corrects it. A run with the cap off never looks at it.
// Run always returns nil when it stops.
func (c *Controller) Run(ctx context.Context) error {
	defer c.removeOwnQuota()

	// timer starts the next retry or recheck. A Set replaces it with a pass at once.
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
		case <-c.wake:
		case <-timerC:
		}
		if ctx.Err() != nil {
			return nil
		}
		if timer != nil {
			timer.Stop()
			timerC = nil
		}

		if wait := c.reconcile(ctx); wait > 0 {
			timer = time.NewTimer(wait)
			timerC = timer.C
		}
	}
}

type passResult struct {
	// cpus is the logical CPU count read in the pass, or 0.
	cpus int
	// quota and effective come from the last inspection of the pass. checked is false when no inspection ran.
	// A failed inspection leaves both unknown.
	quota     Quota
	effective Quota
	checked   bool
	// err is an unexpected failure.
	err error
	// unsupported is set when enforcement is unavailable by design.
	unsupported *UnsupportedError
}

// setErr stores err as unsupported when it reports that, and as an unexpected failure otherwise.
func (r *passResult) setErr(err error) {
	if !errors.As(err, &r.unsupported) {
		r.err = err
	}
}

func isUnsupported(err error) bool {
	var unsupported *UnsupportedError
	return errors.As(err, &unsupported)
}

// reconcile runs one pass for the latest request: inspect, apply if needed, then verify.
// It returns the time to wait before the next pass, or 0 when only a Set starts the next pass.
func (c *Controller) reconcile(ctx context.Context) time.Duration {
	c.mu.Lock()
	req, gen := c.req, c.gen
	// Wakes sent before this point are covered by this pass, so they must not start another pass.
	select {
	case <-c.wake:
	default:
	}
	c.mu.Unlock()

	if !req.Enabled() {
		if !c.owned {
			// A stale pass may have dropped ownership without publishing, so the state is settled here without any
			// backend call.
			return c.finish(ctx, gen, passResult{})
		}
		return c.removeQuota(ctx, gen)
	}

	var res passResult
	n, err := c.logicalCPUs(ctx)
	if err != nil {
		res.setErr(err)
		return c.finish(ctx, gen, res)
	}
	res.cpus = n
	target := req.TargetCPUs(n)
	if !c.current(ctx, gen) {
		return 0
	}

	ins, err := c.inspect(ctx)
	res.checked = true
	if err != nil {
		res.setErr(err)
		return c.finish(ctx, gen, res)
	}
	res.quota, res.effective = ins.Service, ins.Effective
	found := checkResult(ins.Service, target, n)
	if found == nil {
		// A matching quota is adopted, so that it is removed when the cap goes off or when Run stops. This happens even
		// when a newer Set makes this pass stale, so it is done here and not in finish.
		c.setOwned(true, ins.Service)
		return c.finish(ctx, gen, res)
	}
	if !c.startChange(ctx, gen) {
		return 0
	}

	timedOut, applyErr := c.apply(ctx, target)
	applyUnsupported := isUnsupported(applyErr)
	if !applyUnsupported {
		c.setOwned(true, Quota{})
	}
	if !c.current(ctx, gen) {
		return 0
	}

	ins, err = c.inspect(ctx)
	res.quota, res.effective = ins.Service, ins.Effective
	switch {
	case applyUnsupported:
		if err == nil && checkResult(ins.Service, target, n) == nil {
			// Like the first check, a check that finds the target quota adopts it, also when Apply did not write it.
			c.setOwned(true, ins.Service)
		}
		res.setErr(applyErr)
	case isUnsupported(err):
		// Enforcement is unavailable by design, so a failed Apply is not worth a retry.
		res.setErr(err)
	case err != nil && applyErr == nil:
		res.err = err
	case err != nil:
		res.err = errors.Join(applyErr, err)
	default:
		checkErr := checkResult(ins.Service, target, n)
		if checkErr == nil {
			// The write may have landed despite an Apply error, so the verified quota is the one to remove on exit.
			c.setOwned(true, ins.Service)
		}
		switch {
		case applyErr != nil && !timedOut:
			res.err = applyErr
		case checkErr != nil:
			res.err = errors.Join(applyErr, checkErr)
		default:
			// After a timeout only the inspection decides: the quota may be right despite the error.
			if applyErr != nil {
				c.log.Warnw("The CPU quota is as expected although the change failed", "error.message", applyErr.Error())
			}
			c.log.Infow("Set the CPU quota to match the requested CPU limit", "found", found.Error())
		}
	}
	return c.finish(ctx, gen, res)
}

// removeQuota runs one pass with the cap off. It removes the owned quota when mayRemove allows it. Otherwise it forgets
// the quota and changes nothing.
// It returns the time to wait before the next pass, or 0 when only a Set starts the next pass.
func (c *Controller) removeQuota(ctx context.Context, gen uint64) time.Duration {
	var res passResult
	ins, err := c.inspect(ctx)
	res.checked, res.quota, res.effective = true, ins.Service, ins.Effective
	switch {
	case isUnsupported(err):
		// Enforcement is unavailable by design, so the controller cannot remove the quota now or later.
		c.setOwned(false, Quota{})
	case err != nil:
		res.err = err
	case !c.mayRemove(ins.Service):
		if ins.Service.Kind == QuotaNone {
			c.log.Info("There is no CPU quota to remove")
		} else {
			c.log.Info("The CPU quota is not the one the agent set, so it is not removed")
		}
		c.setOwned(false, Quota{})
	default:
		if !c.startChange(ctx, gen) {
			return 0
		}
		err := c.remove(ctx)
		switch {
		case err == nil:
			c.log.Info("Asked to remove the CPU quota of the Agent because the CPU limit is off")
			c.setOwned(false, Quota{})
		case isUnsupported(err):
			c.setOwned(false, Quota{})
		default:
			res.err = err
		}
	}
	return c.finish(ctx, gen, res)
}

// apply calls Backend.Apply with a deadline. timedOut is true when Apply failed because a deadline passed.
func (c *Controller) apply(ctx context.Context, cpus float64) (timedOut bool, err error) {
	callCtx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	if err := c.backend.Apply(callCtx, cpus); err != nil {
		// Apply can return the deadline error before callCtx reports it.
		timedOut = ctx.Err() == nil &&
			(errors.Is(err, context.DeadlineExceeded) || errors.Is(callCtx.Err(), context.DeadlineExceeded))
		return timedOut, fmt.Errorf("failed to change the CPU quota: %w", err)
	}
	return false, nil
}

func (c *Controller) logicalCPUs(ctx context.Context) (int, error) {
	callCtx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	n, err := c.backend.LogicalCPUs(callCtx)
	if err != nil {
		return 0, fmt.Errorf("failed to read the logical CPU count: %w", err)
	}
	if n < 1 {
		return 0, fmt.Errorf("invalid logical CPU count %d", n)
	}
	return n, nil
}

func (c *Controller) remove(ctx context.Context) error {
	callCtx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	if err := c.backend.Remove(callCtx); err != nil {
		return fmt.Errorf("failed to remove the CPU quota: %w", err)
	}
	return nil
}

func (c *Controller) inspect(ctx context.Context) (Inspection, error) {
	callCtx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	ins, err := c.backend.Inspect(callCtx)
	if err != nil {
		return Inspection{}, fmt.Errorf("failed to inspect the CPU quota: %w", err)
	}
	// Consumers of the snapshot may encode it as JSON, which fails on NaN and Inf, so such a quota is a failed read.
	if !isFinite(ins.Service) {
		return Inspection{}, fmt.Errorf("invalid CPU quota %v", ins.Service.CPUs)
	}
	if !isFinite(ins.Effective) {
		// The effective quota is only shown, so a bad value does not fail the check.
		ins.Effective = Quota{}
	}
	return ins, nil
}

// isFinite reports whether q has no value or a finite value.
func isFinite(q Quota) bool {
	return q.Kind != QuotaSet || (!math.IsNaN(q.CPUs) && !math.IsInf(q.CPUs, 0))
}

// checkResult returns nil when service is a quota of target CPUs.
func checkResult(service Quota, target float64, logicalCPUs int) error {
	switch {
	case service.Kind == QuotaUnknown:
		return errors.New("the agent CPU quota is not confirmed")
	case service.Kind == QuotaNone:
		return fmt.Errorf("no CPU quota is set, expected %.2f CPUs", target)
	case !quotaMatches(service.CPUs, target, logicalCPUs):
		return fmt.Errorf("the CPU quota is %.2f CPUs, expected %.2f CPUs", service.CPUs, target)
	default:
		return nil
	}
}

// quotaMatches reports whether a quota of cpus CPUs is within the rounding tolerance of target CPUs.
func quotaMatches(cpus, target float64, logicalCPUs int) bool {
	// The tolerance covers how an operating system rounds a stored quota: 1% of one CPU, or 1/10000 of the host when
	// that is larger. It is inclusive, with a small margin for float rounding.
	// The check is written so that anything not within the tolerance, including an invalid number, is a mismatch.
	return math.Abs(cpus-target) <= max(0.01, float64(logicalCPUs)/10000)+1e-9
}

// sameQuota reports whether a and b are the same quota. Both are read from the backend, so only a float rounding
// difference is allowed. Any other change may come from an admin.
func sameQuota(a, b Quota) bool {
	return a.Kind == QuotaSet && b.Kind == QuotaSet && math.Abs(a.CPUs-b.CPUs) <= 1e-6
}

func (c *Controller) current(ctx context.Context, gen uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return ctx.Err() == nil && gen == c.gen
}

// startChange marks the change of the quota as running and publishes it. It returns false when the pass is stale.
// A stale pass leaves the flags to the next pass, which sets them again or clears them in finish.
func (c *Controller) startChange(ctx context.Context, gen uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx.Err() != nil || gen != c.gen {
		return false
	}
	c.changing = true
	c.publishLocked()
	return true
}

// setOwned records whether the controller owns the quota and the verified owned quota. Only Run calls it.
func (c *Controller) setOwned(owned bool, q Quota) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.owned, c.ownedQuota = owned, q
}

// mayRemove reports whether Remove may run for the quota this controller owns, given the service quota found by a
// check. The backend does not tell who set a quota, so an admin may have changed it. Remove is allowed only when the
// quota is owned and one of these is true:
//   - the service quota is not confirmed, for example while a reload is not finished. There is no value to compare,
//     and Remove clears only the quota that the agent's own mechanism holds;
//   - a quota is set and the controller has no verified quota, for example after a failed Apply;
//   - a quota is set and it is the same as the last verified quota, with only a float rounding difference.
//
// When no quota is set, or a different quota is set, someone else changed it, so it is left alone.
func (c *Controller) mayRemove(service Quota) bool {
	if !c.owned {
		return false
	}
	switch service.Kind {
	case QuotaUnknown:
		return true
	case QuotaSet:
		return c.ownedQuota.Kind == QuotaUnknown || sameQuota(service, c.ownedQuota)
	default:
		return false
	}
}

// removeOwnQuota removes the quota this controller still owns, when mayRemove allows it.
// It runs when Run stops, so ctx of Run is already done.
func (c *Controller) removeOwnQuota() {
	if !c.owned {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownRemoveTimeout)
	defer cancel()
	ins, err := c.inspect(ctx)
	if err != nil {
		if !isUnsupported(err) {
			c.log.Warnw("Failed to check the CPU quota when stopping, the quota is not removed", "error.message", err.Error())
		}
		return
	}
	if !c.mayRemove(ins.Service) {
		return
	}
	if err := c.remove(ctx); err != nil && !isUnsupported(err) {
		c.log.Warnw("Failed to remove the CPU quota when stopping", "error.message", err.Error())
	}
}

// finish stores res if the pass is still current and publishes the snapshot if it changed.
// It returns the time to wait before the next pass, or 0 when only a Set starts the next pass.
func (c *Controller) finish(ctx context.Context, gen uint64, res passResult) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx.Err() != nil || gen != c.gen {
		return 0
	}

	if res.cpus > 0 {
		c.cpus = res.cpus
	}
	if res.checked {
		c.quota, c.effective = res.quota, res.effective
	}
	if !c.req.Enabled() && !c.owned {
		// With the cap off, the quotas are shown only while an owned quota is being removed.
		c.quota, c.effective = Quota{}, Quota{}
	}
	c.changing = false

	switch {
	case res.unsupported != nil:
		if !c.unsupported || c.reason != res.unsupported.Reason {
			c.log.Infow("CPU limit enforcement is not supported on this host", "reason", res.unsupported.Reason)
		}
		c.failed, c.unsupported, c.err, c.reason = false, true, nil, res.unsupported.Reason
	case res.err != nil:
		c.failed, c.err = true, res.err
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
		// With the cap off, removeQuota logs how the removal ended.
		if c.failed && c.req.Enabled() {
			c.log.Info("CPU limit enforcement recovered")
		}
		c.failed, c.unsupported, c.err, c.reason = false, false, nil, ""
	}
	if !c.failed {
		c.closeReadyLocked()
		c.retryDelay, c.loggedErr = 0, ""
	}
	if !reflect.DeepEqual(c.published, c.snapshotLocked()) {
		c.publishLocked()
	}

	switch {
	case c.failed:
		c.retryDelay = min(max(2*c.retryDelay, retryMinDelay), retryMaxDelay)
		return c.retryDelay
	case c.req.Enabled() && !c.unsupported:
		return recheckInterval
	default:
		return 0
	}
}

func (c *Controller) closeReadyLocked() {
	if !c.readyClosed {
		c.readyClosed = true
		close(c.ready)
	}
}

func (c *Controller) publishLocked() {
	s := c.snapshotLocked()
	c.published = s
	select {
	case <-c.updates:
	default:
	}
	c.updates <- s
}

func (c *Controller) snapshotLocked() Snapshot {
	s := Snapshot{
		State: DeriveState(StateInput{
			CapRequested: c.req.Enabled(),
			Removing:     !c.req.Enabled() && c.owned,
			Failed:       c.failed,
			Changing:     c.changing,
			Unsupported:  c.unsupported,
		}),
		Configured:     c.req,
		ActiveQuota:    c.quota,
		EffectiveQuota: c.effective,
		Err:            c.err,
	}
	if c.cpus > 0 {
		s.TargetCPUs = c.req.TargetCPUs(c.cpus)
	}
	if s.State == StateUnsupported {
		s.Reason = c.reason
	}
	return s
}
