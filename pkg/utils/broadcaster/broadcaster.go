package broadcaster

import (
	"context"
	"reflect"
)

// Broadcaster is a helper that tracks the current value of some piece of
// data and forwards changes to a list of subscribers. It is for situations
// where a variable list of subscribers need to observe some piece of state,
// but it is important that the component that owns that state doesn't block.
// It forwards data via synchronous channels, and subscribers can choose to
// receive only the latest value, or to buffer changes up to some configurable
// limit.
//
// For best results, Broadcaster's input should be owned and accessed by a
// single goroutine, and that goroutine is responsible for providing updates
// in the correct order. Broadcaster is still "safe" to use from multiple
// goroutines, but its intended guarantees no longer apply: Broadcaster was
// written to track atomic values from an authoritative source. If multiple
// goroutines can write to it then there is no longer a well-defined "current"
// value, and you might want to consider an alternate pattern.
// Broadcaster has the following constraints / performance guarantees:
//
//   - Broadcaster takes ownership of any values that are sent to it. If
//     appropriate for the data being observed, Broadcaster's owner should
//     create a deep copy before passing it in. If the datatype is a pointer
//     or contains pointers, subscribers should make their own deep copies
//     before modifying them.
//
//     The most reliable way to guarantee safety is to use Broadcaster only
//     with value types / shallow structs.
//
//     The most efficient way to guarantee safety (unless the required heap
//     allocations are prohibitive) is to use Broadcaster with a pointer type
//     that will never be modified, and to have trustworthy subscribers.
//
//   - The input channel is weakly non-blocking: it blocks only for the time
//     it takes to copy the received values to an internal buffer (which means
//     in practice it will never block unless you write to it in a spin lock).
//     In particular, the input is unaffected by congestion or errors in its
//     subscribers.
//
//   - For a subscriber with buffer length n, the output channel will always
//     return the oldest value that has not yet been sent on that channel among
//     the n most recent values since the subscription was started. In
//     particular, a subscriber with buffer length 0 will always receive the
//     most recent value at the time of the read.
//
//   - If a subscriber channel has already received the n most recent values,
//     reads will block until a new value is set.
//
//   - A new subscription will not hard-block on its first read, i.e. it is always
//     primed with the current value.
//
// Broadcaster can monitor the entire lifecycle of components, including the
// shutdown state of terminating components, so instead of an all-or-nothing
// context it uses a manual shutdown to allow for graceful delivery of the
// final values.
//
// To indicate that there will be no more values, and gradually remove
// subscribers as they reach the final value, call close(b.InputChan).
// The run loop terminates when all subscribers are caught up or canceled.
//
// To shutdown Broadcaster immediately, closing all subscribers regardless
// of whether they have received the final values, call Broadcaster.Close.
//
// To shutdown gradually, giving subscribers 5 seconds to catch up:
//
//	close(b.InputChan)
//	select {
//	case <-b.Done():
//	case <-time.After(5*time.Second):
//	  b.Close()
//	}
//
// A caller that wants to clean up Broadcaster's data and run loop is
// responsible for choosing one of these three options on shutdown.
// A caller that needs to wait until Broadcaster's run loop is completely
// finished (e.g. tests waiting for delivery of the final shutdown state)
// should wait on b.Done() after initiating shutdown.
type Broadcaster[T any] struct {
	// Values to be broadcasted should be sent to InputChan.
	InputChan chan T

	// Subscribe sends requests to subscribeChan where they are received
	// by runLoop and added to subscribers.
	subscribeChan chan subscribeRequest[T]

	// getChan is used by Get, which provides a way for non-subscribers to
	// do a one-time read of the most recent value.
	getChan chan T

	// Close writes to shutdownChan to notify Broadcaster that it should
	// close all subscribers and return.
	// Note that this signal uses a write rather than closing shutdownChan,
	// because closing a channel twice causes a panic, whereas writing to
	// it twice can be cancelled by selecting on doneChan as well.
	// (Hopefully callers won't invoke Close twice, but if they do it's
	// polite to avoid panicking.)
	shutdownChan chan struct{}

	// doneChan is closed when the run loop exits. It is exposed via
	// Done(), and callers can use it to wait until the Broadcaster
	// has completely finished.
	doneChan chan struct{}

	/////////////////////////////////////////////////////////////////////////
	// Internal run loop state. Fields below could be local variables
	// in the run loop, but we break the run loop into individual iterations
	// and expose its fields to allow for deterministic unit tests.

	// A buffer with the most recent observed states. len(buffer) is
	// the largest buffer request that will be accepted from a subscriber.
	buffer []T

	// The list of current subscribers. A subscriber is removed from this
	// list when its context ends.
	subscribers []subscriber[T]

	// The cases that will be passed to reflect.Select. In order (see the
	// index* constants below):
	// - InputChan listener
	// - subscribeChan listener
	// - shutdownChan listener
	// - getChan writer
	// - For each subcsriber, in the same order as the subscribers array,
	//   two cases: the first reading the subscriber's context channel,
	//   the second
	selectCases []reflect.SelectCase

	// index is incremented with every new value, and corresponds to the
	// number of values that have been received so far. The next value
	// to arrive will be placed in buffer[index % len(buffer)] (so buffer
	// positions wrap around when the buffer limit is reached), and if
	// index > 0 then the most recent received value is in
	// buffer[(index-1) % len(buffer)].
	index int64
}

// subscribeRequest is sent to Broadcaster.subscribeChan to add a new
// subscriber.
type subscribeRequest[T any] struct {
	ctx        context.Context
	outputChan chan T
}

type subscriber[T any] struct {
	// The channel to send new values to.
	outputChan chan T

	// ctxCase is the case of the reflect.Select call that listens for the
	// subscriber's context to end. This is a mutable pointer into Broadcaster's
	// selectCases array.
	ctxCase *reflect.SelectCase

	// valueCase is the case of the reflect.Select call that waits to send new
	// values to the subscriber. When the subscriber has already read the most
	// recent value, valueCase.chan is set to nil to prevent additional sends.
	// When a new value arrives, all subscribers have valueCase.chan reset
	// to their outputChan. This is a mutable pointer into Broadcaster's
	// selectCases array.
	valueCase *reflect.SelectCase
}

// New creates a Broadcaster and starts its run loop. The caller is responsible
// for calling (*Broadcaster).Close to terminate the run loop when Broadcaster
// should be cleaned up. (Cleanup is explicit rather than via a context so
// subscribers can optionally read the final values before shutdown.)
func New[T any](initialValue T, maxBuffer int) *Broadcaster[T] {
	b := &Broadcaster[T]{
		// 32 is probably an over-cautious buffer here, but preventing blocking
		// in the input is the most important design goal.
		InputChan:   make(chan T, 32),
		buffer:      make([]T, maxBuffer),
		subscribers: []subscriber[T]{},
	}
	go b.runLoop()
	return b
}

func (b *Broadcaster[T]) runLoop() {
	defer close(b.doneChan)
	for {
		b.runLoopIterate()
	}
}

// The interior of the run loop is split into its own helper function so
// we can deterministically test Broadcaster's behavior in the unit tests.
func (b *Broadcaster[T]) runLoopIterate() {

}

func (b *Broadcaster[T]) Subscribe(context context.Context, bufferLen int) chan T {
	req := subscribeRequest[T]{
		ctx:        context,
		outputChan: make(chan T),
	}
	select {
	case b.subscribeChan <- req:
		// If the request goes through then we were successful, we can return
		// the output channel.
	case <-b.doneChan:
		// The Broadcaster has been closed, return a closed channel to indicate
		// there will be no more data.
		close(req.outputChan)
	}
	return req.outputChan
}

func (b *Broadcaster[T]) Get() T {
	select {
	case value := <-b.getChan:
		return value
	case <-b.doneChan:
	}
	return b.buffer[0]
}

// Close all subscriber channels, discarding any unsent values, and terminate
// Broadcaster's run loop.
// Close returns immediately once the shutdown signal is sent. Callers that
// want to make sure the run loop has terminated completely should wait on
// b.Done() after calling Close.
// Callers who are shutting down but want Broadcaster to finish sending
// the existing values to its subscribers before terminating should instead
// call close(b.InputChan).
func (b *Broadcaster[T]) Close() {
	// Try to send a shutdown signal, but cancel out if doneChan returns because
	// that means it already happened.
	select {
	case b.shutdownChan <- struct{}{}:
	case <-b.doneChan:
	}
}

func (b *Broadcaster[T]) Done() <-chan struct{} {
	return b.doneChan
}
