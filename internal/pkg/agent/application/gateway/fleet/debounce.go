package fleet

import "time"

type debouncer interface {
	Elapsed() <-chan time.Time
}

type debouncerFactory func() debouncer

type timerDebouncer struct {
	t *time.Timer
}

func (td *timerDebouncer) Elapsed() <-chan time.Time {
	return td.t.C
}

func newTimerDebouncer(d time.Duration) *timerDebouncer {
	return &timerDebouncer{t: time.NewTimer(d)}
}
