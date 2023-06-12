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
	// - For each subscriber, in the same order as the subscribers array,
	//   two cases: the first reading the subscriber's context channel,
	//   the second
	selectCases []reflect.SelectCase

	// index is initialized to zero and incremented with every new value, and
	// is used to track where subscribers are in Broadcaster's buffer relative
	// to the most recent value. Broadcaster's most recent value is in
	// buffer[index % len(buffer)] (i.e. "index" is the position of the current
	// value once we account for wrapping around at the end of the array).
	index int

	// shuttingDown indicates that InputChan has been closed. When this is true,
	// subscribers who finish reading all pending values have their listener
	// channels closed and are removed from the subscriber list, and when all
	// subscribers are removed the run loop returns.
	shuttingDown bool
}

// constant indices representing the order of the cases in
// Broadcaster.selectCases
const (
	indexInputCase           = 0
	indexSubscribeCase       = 1
	indexShutdownCase        = 2
	indexGetCase             = 3
	indexFirstSubscriberCase = 4
)

// subscribeRequest is sent to Broadcaster.subscribeChan to add a new
// subscriber.
type subscribeRequest[T any] struct {
	ctx          context.Context
	listenerChan chan T
	bufferLen    int
}

type subscriber[T any] struct {
	// The channel to send new values to.
	listenerChan chan T

	// The index of the next value that this subscriber should receive.
	// If subscriber.index == Broadcaster.index then the subscriber is waiting
	// to receive the most recent vaue. If subscriber.index > Broadcaster.index
	// then it has received all current values and will block until a new one
	// arrives.
	index int

	// How many values this subscriber will buffer in between reads. If bufferLen
	// is zero, this subscriber will always read the most recent value, otherwise
	// it will read the most recent values in order up to a limit of bufferLen.
	// bufferLen must be at most len(Broadcaster.buffer).
	bufferLen int

	// ctxCase is the case of the reflect.Select call that listens for the
	// subscriber's context to end. This is a mutable pointer into Broadcaster's
	// selectCases array.
	ctxCase *reflect.SelectCase

	// listenerCase is the case of the reflect.Select call that waits to send new
	// values to the subscriber. When the subscriber has already read the most
	// recent value, listenerCase.chan is set to nil to prevent additional sends.
	// When a new value arrives, all subscribers have listenerCase.chan reset
	// to their outputChan. This is a mutable pointer into Broadcaster's
	// selectCases array.
	listenerCase *reflect.SelectCase
}

// New creates a Broadcaster and starts its run loop. The caller is responsible
// for calling (*Broadcaster).Close to terminate the run loop when Broadcaster
// should be cleaned up. (Cleanup is explicit rather than via a context so
// subscribers can optionally read the final values before shutdown.)
func New[T any](initialValue T, maxBuffer int) *Broadcaster[T] {
	b := new(initialValue, maxBuffer)
	go b.runLoop()
	return b
}

// Subscribe adds a new subscriber to Broadcaster, returning a channel that
// the subscriber can listen on for new values. While active, the channel
// will return all changes to Broadcaster's tracked value, storing up to
// bufferLen most recent values if the subscriber does not read them in time.
// bufferLen values larger than the maxBuffer value passed to broadcaster.New
// are capped. If bufferLen is zero, the listener channel always returns the
// most recent value at the time of the read.
// The channel will be closed when the given context expires, or when
// Broadcaster itself shuts down. All returned channels are guaranteed to
// produce at least one value on initial subscription, even if Broadcaster
// has shut down.
func (b *Broadcaster[T]) Subscribe(context context.Context, bufferLen int) chan T {
	req := subscribeRequest[T]{
		ctx:          context,
		listenerChan: make(chan T),
		bufferLen:    bufferLen,
	}
	select {
	case b.subscribeChan <- req:
		// If the request goes through then we were successful, we can return
		// the output channel.
		return req.listenerChan

	case <-b.doneChan:
		// The Broadcaster has shut down. Return a closed channel with the final
		// value buffered inside, so we don't break callers that rely on our
		// guarantee that the first read always succeeds.
		closedChan := make(chan T, 1)
		closedChan <- b.currentValue()
		close(closedChan)
		return closedChan
	}
}

// Get returns Broadcaster's current value. It always succeeds, even if
// Broadcaster has been closed, and it always gives the most recent value
// at the time of the call. (However, remember that it's possible for the
// value to change again in between the time that Get reads it and the
// time that Get returns to the caller. If you need to know about changes
// to the current value, use Subscribe instead.)
func (b *Broadcaster[T]) Get() T {
	select {
	case value := <-b.getChan:
		return value
	case <-b.doneChan:
		// If doneChan is closed, then the run loop has shut down and the current
		// value will never change again, so it is safe to read it directly from
		// the caller's goroutine.
		return b.currentValue()
	}
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

// Done returns a channel callers can wait on to detect that Broadcaster has
// shut down. When this channel is closed, Broadcaster's run loop has ended
// and it will not send any more values.
func (b *Broadcaster[T]) Done() <-chan struct{} {
	return b.doneChan
}

// new is the internal implementation of New that does everything except
// start the run loop, for tests that want to handle execution steps
// manually/synchronously.
func new[T any](initialValue T, maxBuffer int) *Broadcaster[T] {
	return &Broadcaster[T]{
		// 32 is probably an over-cautious buffer here, but preventing blocking
		// in the input is the most important design goal.
		InputChan: make(chan T, 32),
		// The array is maxBuffer+1 because we need to store the current value
		// in addition to any "buffered" values. If maxBuffer is 0, then we
		// store only the current value and the array is length 1. If
		// maxBuffer is 5, then we will store 5 previous values in addition to
		// the current one.
		buffer: make([]T, maxBuffer+1),
	}
}

// runLoop is Broadcaster's main loop, which listens for updates from the
// input and sends any buffered values to registered subscribers.
// Its logic is implemented in runLoopIterate.
func (b *Broadcaster[T]) runLoop() {
	defer close(b.doneChan)
	for {
		b.runLoopIterate()
	}
}

// runLoopIterate is the interior of the run loop, which is split into its own
// helper function so we can deterministically test Broadcaster's behavior in
// the unit tests.
func (b *Broadcaster[T]) runLoopIterate() {
	b.drainInput()
	chosen, recvValue, recvOK := reflect.Select(b.selectCases)
	switch chosen {
	case indexInputCase:
		if recvOK {
			// We've received a new value, add it to the internal buffer and update
			// subscriber state.
			value := recvValue.Interface().(T)
			b.handleNewInput(value)
			b.updateSubscribers()
		} else {
			// The input channel is closed, begin shutting down. Setting shuttingDown
			// to true means subscribers will be removed as they finish reading
			// buffered values, and when all active subscribers are removed runLoop
			// will return. We also clear the channel in input's select case, so we
			// can keep iterating without hitting this case again.
			b.shuttingDown = true
			b.selectCases[indexInputCase].Chan = reflect.ValueOf(nil)
		}

	case indexSubscribeCase:
		req := recvValue.Interface().(subscribeRequest[T])
		b.handleNewSubscriber(req)

	case indexShutdownCase:
		b.shutdown()

	case indexGetCase:
		// Someone has read our current state, but we don't need to do anything.

	default:
		// The selected case is from one of our subscribers.
		// Each subscriber covers two cases, figure out which one we got.
		subscriberIndex := (chosen - indexFirstSubscriberCase) / 2
		if (chosen-indexFirstSubscriberCase)%2 == 0 {
			// The first case for each subscriber is the shutdown channel -- remove
			// this subscriber from the list.
			b.removeSubscriber(subscriberIndex)
		} else {
			// The second case for each subscriber is their listener channel -- they
			// just received a value, advance their position in the buffer.
			b.advanceSubscriber(subscriberIndex)
		}
	}
}

// drainInput reads as many values as possible from the input channel and
// updates subscriber state if there were any new values.
// This is called in the run loop before the main select, to make sure input
// values get priority over any other signal.
func (b *Broadcaster[T]) drainInput() {
	receivedInput := false
	for {
		select {
		case value := <-b.InputChan:
			b.handleNewInput(value)
			receivedInput = true
		default:
			if receivedInput {
				// If we received any values, refresh the subscriber state.
				b.updateSubscribers()
			}
			return
		}
	}
}

// currentValue is a simple internal helper to return the most recent value
// in the buffer.
func (b *Broadcaster[T]) currentValue() T {
	return b.buffer[b.index%len(b.buffer)]
}

// handleNewInput adds an incoming value to the internal buffer. Callers should
// also call updateSubscribers() when all changes are done. (handleNewInput
// doesn't update subscribers itself so that we can avoid redundant passes
// through the subscriber list when draining the input channel. In practice
// this is rare, but if the input channel ever does gets backed up then
// draining it is our highest priority.)
func (b *Broadcaster[T]) handleNewInput(value T) {
	b.index++
	b.buffer[b.index%len(b.buffer)] = value
}

func (b *Broadcaster[T]) handleNewSubscriber(req subscribeRequest[T]) {
	// Add two select cases for the new subscriber, one for its context channel
	// and one for its listener channel.
	b.selectCases = append(b.selectCases,
		reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(req.ctx.Done()),
		},
		reflect.SelectCase{
			Dir:  reflect.SelectSend,
			Chan: reflect.ValueOf(req.listenerChan),
			Send: reflect.ValueOf(b.currentValue()),
		},
	)

	// Cap the requested buffer length at the maximum set when Broadcaster
	// was created.
	// Subtlety: in order for a bufferLen of 0 to correspond to the most
	// recent value, the actual buffer inside Broadcaster must have length
	// at least bufferLen+1, so bufferLen is capped at len(buffer)-1.
	bufferLen := req.bufferLen
	if bufferLen > len(b.buffer)-1 {
		bufferLen = len(b.buffer) - 1
	}
	b.subscribers = append(b.subscribers, subscriber[T]{
		listenerChan: req.listenerChan,
		index:        b.index, // Start with the current value
		bufferLen:    bufferLen,
		ctxCase:      &b.selectCases[len(b.selectCases)-2],
		listenerCase: &b.selectCases[len(b.selectCases)-1],
	})
}

// Close the target subscriber's listener channel and remove it from the lists
// of subscribers and select cases.
func (b *Broadcaster[T]) removeSubscriber(subscriberIndex int) {
	close(b.subscribers[subscriberIndex].listenerChan)
	b.subscribers = append(b.subscribers[:subscriberIndex], b.subscribers[subscriberIndex+1:]...)
	// Index in the select cases is the index of the first subscriber
	// plus two cases for each subscriber.
	caseIndex := indexFirstSubscriberCase + 2*subscriberIndex
	b.selectCases = append(b.selectCases[:caseIndex], b.selectCases[caseIndex+2:]...)
}

// advanceSubscriber is called when a subscriber reads a value, to advance
// it to the next index and either prepare its listener select case with the
// next value or block it if there are no more values.
func (b *Broadcaster[T]) advanceSubscriber(subscriberIndex int) {
	s := &b.subscribers[subscriberIndex]
	s.index++
	if s.index > b.index {
		// No more values to read, block the channel for now
		s.listenerCase.Chan = reflect.ValueOf(nil)
	} else {
		// Load the send channel with the buffer value at s.index
		s.listenerCase.Send = reflect.ValueOf(b.buffer[s.index%len(b.buffer)])
	}
}

// updateSubscribers is called after new input comes in to advance subscriber
// position if necessary and reactivate their listener channels with the new
// values.
func (b *Broadcaster[T]) updateSubscribers() {
	for i := range b.subscribers {
		subscriber := &b.subscribers[i]
		if subscriber.index <= b.index {
			// The subscriber hasn't read the most recent value, unblock its channel.
			subscriber.listenerCase.Chan = reflect.ValueOf(subscriber.listenerChan)
		}
		if subscriber.index < b.index-subscriber.bufferLen {
			// If bufferLen is 0, then subscriber.index must be at least b.index,
			// since it only receives the most recent value; therefore if
			// bufferLen is n, subscriber.index must be at least b.index-n.
			// (Note that subscriber.bufferLen is at most len(b.buffer)-1, so
			// the oldest and newest values in the circular buffer don't overlap.)
			subscriber.index = b.index - subscriber.bufferLen
			subscriber.listenerCase.Send = reflect.ValueOf(
				b.buffer[subscriber.index%len(b.buffer)])
		}
		// If subscriber.index didn't need to be advanced, then its listener
		// case already contains the correct Send value.
	}
}

// shutdown sets the shuttingDown flag and closes all subscribers, so the
// run loop will return after the current iteration.
func (b *Broadcaster[T]) shutdown() {
	b.shuttingDown = true

	// Possibly overkill, but remove subscribers in reverse order so the array
	// can be truncated as we go instead of copying the whole thing each step.
	for i := len(b.subscribers) - 1; i >= 0; i-- {
		b.removeSubscriber(i)
	}
}
