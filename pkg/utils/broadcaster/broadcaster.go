package broadcaster

import "context"

type Broadcaster[T any] struct {
	buffer      []T
	subscribers []subscriber[T]
	index       int64
}

type subscriber[T any] struct {
}

func New[T any](value T, maxBuffer int) *Broadcaster[T] {
	return nil
}

func (b *Broadcaster[T]) Set(value T) {
	b.index++
}

func (b *Broadcaster[T]) Subscribe(context context.Context, bufferLen int) chan T {
	// TODO
	b.subscribers = append(b.subscribers, subscriber[T]{})
	return make(chan T)
}

func (b *Broadcaster[T]) Get() T {
	return b.buffer[0]
}
