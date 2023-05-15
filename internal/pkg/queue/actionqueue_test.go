// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//nolint:dupl // lots of casting in test cases
package queue

import (
	"container/heap"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
)

type mockAction struct {
	mock.Mock
}

func (m *mockAction) String() string {
	args := m.Called()
	return args.String(0)
}

func (m *mockAction) Type() string {
	args := m.Called()
	return args.String(0)
}

func (m *mockAction) ID() string {
	args := m.Called()
	return args.String(0)
}

func (m *mockAction) AckEvent() fleetapi.AckEvent {
	args := m.Called()
	return args.Get(0).(fleetapi.AckEvent)
}

func (m *mockAction) StartTime() (time.Time, error) {
	args := m.Called()
	return args.Get(0).(time.Time), args.Error(1)
}

func (m *mockAction) Expiration() (time.Time, error) {
	args := m.Called()
	return args.Get(0).(time.Time), args.Error(1)
}

type mockSaver struct {
	mock.Mock
}

func (m *mockSaver) SetQueue(a []fleetapi.Action) {
	m.Called(a)
}

func (m *mockSaver) Save() error {
	args := m.Called()
	return args.Error(0)
}

func TestNewQueue(t *testing.T) {
	ts := time.Now()
	a1 := &mockAction{}
	a1.On("ID").Return("test-1")
	a1.On("StartTime").Return(ts, nil)
	a2 := &mockAction{}
	a2.On("ID").Return("test-2")
	a2.On("StartTime").Return(ts.Add(time.Second), nil)
	a3 := &mockAction{}
	a3.On("ID").Return("test-3")
	a3.On("StartTime").Return(ts.Add(time.Minute), nil)

	t.Run("nil actions slice", func(t *testing.T) {
		q, err := newQueue(nil)
		require.NoError(t, err)
		assert.NotNil(t, q)
		assert.Empty(t, q)
	})

	t.Run("empty actions slice", func(t *testing.T) {
		q, err := newQueue([]fleetapi.Action{})
		require.NoError(t, err)
		assert.NotNil(t, q)
		assert.Empty(t, q)
	})

	t.Run("ordered actions list", func(t *testing.T) {
		q, err := newQueue([]fleetapi.Action{a1, a2, a3})
		assert.NotNil(t, q)
		require.NoError(t, err)
		assert.Len(t, *q, 3)

		i := heap.Pop(q).(*item)
		assert.Equal(t, "test-1", i.action.ID())
		i = heap.Pop(q).(*item)
		assert.Equal(t, "test-2", i.action.ID())
		i = heap.Pop(q).(*item)
		assert.Equal(t, "test-3", i.action.ID())
		assert.Empty(t, *q)
	})

	t.Run("unordered actions list", func(t *testing.T) {
		q, err := newQueue([]fleetapi.Action{a3, a2, a1})
		require.NoError(t, err)
		assert.NotNil(t, q)
		assert.Len(t, *q, 3)

		i := heap.Pop(q).(*item)
		assert.Equal(t, "test-1", i.action.ID())
		i = heap.Pop(q).(*item)
		assert.Equal(t, "test-2", i.action.ID())
		i = heap.Pop(q).(*item)
		assert.Equal(t, "test-3", i.action.ID())
		assert.Empty(t, *q)
	})

	t.Run("start time error", func(t *testing.T) {
		a := &mockAction{}
		a.On("StartTime").Return(time.Time{}, errors.New("oh no"))
		q, err := newQueue([]fleetapi.Action{a})
		assert.EqualError(t, err, "oh no")
		assert.Nil(t, q)
	})
}

func assertOrdered(t *testing.T, q *queue) {
	t.Helper()
	require.Len(t, *q, 3)
	i := heap.Pop(q).(*item)
	assert.Equal(t, int64(1), i.priority)
	assert.Equal(t, "test-1", i.action.ID())
	i = heap.Pop(q).(*item)
	assert.Equal(t, int64(2), i.priority)
	assert.Equal(t, "test-2", i.action.ID())
	i = heap.Pop(q).(*item)
	assert.Equal(t, int64(3), i.priority)
	assert.Equal(t, "test-3", i.action.ID())

	assert.Empty(t, *q)
}

func Test_ActionQueue_Add(t *testing.T) {
	a1 := &mockAction{}
	a1.On("ID").Return("test-1")
	a2 := &mockAction{}
	a2.On("ID").Return("test-2")
	a3 := &mockAction{}
	a3.On("ID").Return("test-3")

	t.Run("ascending order", func(t *testing.T) {
		aq := &ActionQueue{
			q: &queue{},
		}
		aq.Add(a1, 1)
		aq.Add(a2, 2)
		aq.Add(a3, 3)

		assertOrdered(t, aq.q)
	})

	t.Run("Add descending order", func(t *testing.T) {
		aq := &ActionQueue{
			q: &queue{},
		}
		aq.Add(a3, 3)
		aq.Add(a2, 2)
		aq.Add(a1, 1)

		assertOrdered(t, aq.q)
	})

	t.Run("mixed order", func(t *testing.T) {
		aq := &ActionQueue{
			q: &queue{},
		}
		aq.Add(a1, 1)
		aq.Add(a3, 3)
		aq.Add(a2, 2)

		assertOrdered(t, aq.q)
	})

	t.Run("two items have same priority", func(t *testing.T) {
		aq := &ActionQueue{
			q: &queue{},
		}
		aq.Add(a1, 1)
		aq.Add(a2, 2)
		aq.Add(a3, 2)

		require.Len(t, *aq.q, 3)
		i := heap.Pop(aq.q).(*item)
		assert.Equal(t, int64(1), i.priority)
		assert.Equal(t, "test-1", i.action.ID())
		// next two items have same priority, however the ids may not match insertion order
		i = heap.Pop(aq.q).(*item)
		assert.Equal(t, int64(2), i.priority)
		i = heap.Pop(aq.q).(*item)
		assert.Equal(t, int64(2), i.priority)
		assert.Empty(t, *aq.q)
	})
}

func Test_ActionQueue_DequeueActions(t *testing.T) {
	a1 := &mockAction{}
	a1.On("ID").Return("test-1")
	a2 := &mockAction{}
	a2.On("ID").Return("test-2")
	a3 := &mockAction{}
	a3.On("ID").Return("test-3")

	t.Run("empty queue", func(t *testing.T) {
		aq := &ActionQueue{
			q: &queue{},
		}

		actions := aq.DequeueActions()

		assert.Empty(t, actions)
		assert.Empty(t, *aq.q)
	})

	t.Run("one action from queue", func(t *testing.T) {
		ts := time.Now()
		q := &queue{&item{
			action:   a1,
			priority: ts.Add(-1 * time.Minute).Unix(),
			index:    0,
		}, &item{
			action:   a2,
			priority: ts.Add(2 * time.Minute).Unix(),
			index:    1,
		}, &item{
			action:   a3,
			priority: ts.Add(3 * time.Minute).Unix(),
			index:    2,
		}}
		heap.Init(q)
		aq := &ActionQueue{q, &mockSaver{}}

		actions := aq.DequeueActions()

		require.Len(t, actions, 1)
		assert.Equal(t, "test-1", actions[0].ID())

		require.Len(t, *q, 2)
		i := heap.Pop(q).(*item)
		assert.Equal(t, "test-2", i.action.ID())
		assert.Equal(t, ts.Add(2*time.Minute).Unix(), i.priority)
		i = heap.Pop(q).(*item)
		assert.Equal(t, "test-3", i.action.ID())
		assert.Equal(t, ts.Add(3*time.Minute).Unix(), i.priority)

		assert.Empty(t, *q)
	})

	t.Run("two actions from queue", func(t *testing.T) {
		ts := time.Now()
		q := &queue{&item{
			action:   a1,
			priority: ts.Add(-1 * time.Minute).Unix(),
			index:    0,
		}, &item{
			action:   a2,
			priority: ts.Add(-2 * time.Minute).Unix(),
			index:    1,
		}, &item{
			action:   a3,
			priority: ts.Add(3 * time.Minute).Unix(),
			index:    2,
		}}
		heap.Init(q)
		aq := &ActionQueue{q, &mockSaver{}}

		actions := aq.DequeueActions()

		require.Len(t, actions, 2)
		assert.Equal(t, "test-2", actions[0].ID())
		assert.Equal(t, "test-1", actions[1].ID())

		require.Len(t, *q, 1)
		i := heap.Pop(q).(*item)
		assert.Equal(t, "test-3", i.action.ID())
		assert.Equal(t, ts.Add(3*time.Minute).Unix(), i.priority)

		assert.Empty(t, *q)
	})

	t.Run("all actions from queue", func(t *testing.T) {
		ts := time.Now()
		q := &queue{&item{
			action:   a1,
			priority: ts.Add(-1 * time.Minute).Unix(),
			index:    0,
		}, &item{
			action:   a2,
			priority: ts.Add(-2 * time.Minute).Unix(),
			index:    1,
		}, &item{
			action:   a3,
			priority: ts.Add(-3 * time.Minute).Unix(),
			index:    2,
		}}
		heap.Init(q)
		aq := &ActionQueue{q, &mockSaver{}}

		actions := aq.DequeueActions()

		require.Len(t, actions, 3)
		assert.Equal(t, "test-3", actions[0].ID())
		assert.Equal(t, "test-2", actions[1].ID())
		assert.Equal(t, "test-1", actions[2].ID())

		require.Empty(t, *q)
	})

	t.Run("no actions from queue", func(t *testing.T) {
		ts := time.Now()
		q := &queue{&item{
			action:   a1,
			priority: ts.Add(1 * time.Minute).Unix(),
			index:    0,
		}, &item{
			action:   a2,
			priority: ts.Add(2 * time.Minute).Unix(),
			index:    1,
		}, &item{
			action:   a3,
			priority: ts.Add(3 * time.Minute).Unix(),
			index:    2,
		}}
		heap.Init(q)
		aq := &ActionQueue{q, &mockSaver{}}

		actions := aq.DequeueActions()
		assert.Empty(t, actions)

		require.Len(t, *q, 3)
		i := heap.Pop(q).(*item)
		assert.Equal(t, "test-1", i.action.ID())
		assert.Equal(t, ts.Add(1*time.Minute).Unix(), i.priority)
		i = heap.Pop(q).(*item)
		assert.Equal(t, "test-2", i.action.ID())
		assert.Equal(t, ts.Add(2*time.Minute).Unix(), i.priority)
		i = heap.Pop(q).(*item)
		assert.Equal(t, "test-3", i.action.ID())
		assert.Equal(t, ts.Add(3*time.Minute).Unix(), i.priority)

	})
}

func Test_ActionQueue_Cancel(t *testing.T) {
	a1 := &mockAction{}
	a1.On("ID").Return("test-1")
	a2 := &mockAction{}
	a2.On("ID").Return("test-2")
	a3 := &mockAction{}
	a3.On("ID").Return("test-3")

	t.Run("empty queue", func(t *testing.T) {
		q := &queue{}
		aq := &ActionQueue{q, &mockSaver{}}

		n := aq.Cancel("test-1")
		assert.Zero(t, n)
		assert.Empty(t, *q)
	})

	t.Run("one item cancelled", func(t *testing.T) {
		q := &queue{&item{
			action:   a1,
			priority: 1,
			index:    0,
		}, &item{
			action:   a2,
			priority: 2,
			index:    1,
		}, &item{
			action:   a3,
			priority: 3,
			index:    2,
		}}
		heap.Init(q)
		aq := &ActionQueue{q, &mockSaver{}}

		n := aq.Cancel("test-1")
		assert.Equal(t, 1, n)

		assert.Len(t, *q, 2)
		i := heap.Pop(q).(*item)
		assert.Equal(t, "test-2", i.action.ID())
		assert.Equal(t, int64(2), i.priority)
		i = heap.Pop(q).(*item)
		assert.Equal(t, "test-3", i.action.ID())
		assert.Equal(t, int64(3), i.priority)
		assert.Empty(t, *q)
	})

	t.Run("two items cancelled", func(t *testing.T) {
		q := &queue{&item{
			action:   a1,
			priority: 1,
			index:    0,
		}, &item{
			action:   a1,
			priority: 2,
			index:    1,
		}, &item{
			action:   a3,
			priority: 3,
			index:    2,
		}}
		heap.Init(q)
		aq := &ActionQueue{q, &mockSaver{}}

		n := aq.Cancel("test-1")
		assert.Equal(t, 2, n)

		assert.Len(t, *q, 1)
		i := heap.Pop(q).(*item)
		assert.Equal(t, "test-3", i.action.ID())
		assert.Equal(t, int64(3), i.priority)
		assert.Empty(t, *q)
	})

	t.Run("all items cancelled", func(t *testing.T) {
		q := &queue{&item{
			action:   a1,
			priority: 1,
			index:    0,
		}, &item{
			action:   a1,
			priority: 2,
			index:    1,
		}, &item{
			action:   a1,
			priority: 3,
			index:    2,
		}}
		heap.Init(q)
		aq := &ActionQueue{q, &mockSaver{}}

		n := aq.Cancel("test-1")
		assert.Equal(t, 3, n)
		assert.Empty(t, *q)
	})

	t.Run("no items cancelled", func(t *testing.T) {
		q := &queue{&item{
			action:   a1,
			priority: 1,
			index:    0,
		}, &item{
			action:   a2,
			priority: 2,
			index:    1,
		}, &item{
			action:   a3,
			priority: 3,
			index:    2,
		}}
		heap.Init(q)
		aq := &ActionQueue{q, &mockSaver{}}

		n := aq.Cancel("test-0")
		assert.Zero(t, n)

		assert.Len(t, *q, 3)
		i := heap.Pop(q).(*item)
		assert.Equal(t, "test-1", i.action.ID())
		assert.Equal(t, int64(1), i.priority)
		i = heap.Pop(q).(*item)
		assert.Equal(t, "test-2", i.action.ID())
		assert.Equal(t, int64(2), i.priority)
		i = heap.Pop(q).(*item)
		assert.Equal(t, "test-3", i.action.ID())
		assert.Equal(t, int64(3), i.priority)
		assert.Empty(t, *q)
	})
}

func Test_ActionQueue_Actions(t *testing.T) {
	t.Run("empty queue", func(t *testing.T) {
		q := &queue{}
		aq := &ActionQueue{q, &mockSaver{}}
		actions := aq.Actions()
		assert.Len(t, actions, 0)
	})

	t.Run("non-empty queue", func(t *testing.T) {
		a1 := &mockAction{}
		a1.On("ID").Return("test-1")
		a2 := &mockAction{}
		a2.On("ID").Return("test-2")
		a3 := &mockAction{}
		a3.On("ID").Return("test-3")
		q := &queue{&item{
			action:   a1,
			priority: 1,
			index:    0,
		}, &item{
			action:   a2,
			priority: 2,
			index:    1,
		}, &item{
			action:   a3,
			priority: 3,
			index:    2,
		}}
		heap.Init(q)
		aq := &ActionQueue{q, &mockSaver{}}

		actions := aq.Actions()
		assert.Len(t, actions, 3)
		assert.Equal(t, "test-1", actions[0].ID())
	})
}

func Test_ActionQueue_CancelType(t *testing.T) {
	a1 := &mockAction{}
	a1.On("ID").Return("test-1")
	a1.On("Type").Return("upgrade")
	a2 := &mockAction{}
	a2.On("ID").Return("test-2")
	a2.On("Type").Return("upgrade")
	a3 := &mockAction{}
	a3.On("ID").Return("test-3")
	a3.On("Type").Return("unknown")

	t.Run("empty queue", func(t *testing.T) {
		aq := &ActionQueue{&queue{}, &mockSaver{}}

		n := aq.CancelType("upgrade")
		assert.Equal(t, 0, n)
	})

	t.Run("single item in queue", func(t *testing.T) {
		q := &queue{&item{
			action:   a1,
			priority: 1,
			index:    0,
		}}
		heap.Init(q)
		aq := &ActionQueue{q, &mockSaver{}}

		n := aq.CancelType("upgrade")
		assert.Equal(t, 1, n)
	})

	t.Run("no matches in queue", func(t *testing.T) {
		q := &queue{&item{
			action:   a3,
			priority: 1,
			index:    0,
		}}
		heap.Init(q)
		aq := &ActionQueue{q, &mockSaver{}}

		n := aq.CancelType("upgrade")
		assert.Equal(t, 0, n)
	})

	t.Run("all items cancelled", func(t *testing.T) {
		q := &queue{&item{
			action:   a1,
			priority: 1,
			index:    0,
		}, &item{
			action:   a2,
			priority: 2,
			index:    1,
		}}
		heap.Init(q)
		aq := &ActionQueue{q, &mockSaver{}}

		n := aq.CancelType("upgrade")
		assert.Equal(t, 2, n)
	})
}
