// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Code generated by mockery v2.51.1. DO NOT EDIT.

package kubernetessecrets

import mock "github.com/stretchr/testify/mock"

// mockStore is an autogenerated mock type for the store type
type mockStore struct {
	mock.Mock
}

type mockStore_Expecter struct {
	mock *mock.Mock
}

func (_m *mockStore) EXPECT() *mockStore_Expecter {
	return &mockStore_Expecter{mock: &_m.Mock}
}

// AddConditionally provides a mock function with given fields: key, sd, updateAccess, cond
func (_m *mockStore) AddConditionally(key string, sd secret, updateAccess bool, cond conditionFn) {
	_m.Called(key, sd, updateAccess, cond)
}

// mockStore_AddConditionally_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AddConditionally'
type mockStore_AddConditionally_Call struct {
	*mock.Call
}

// AddConditionally is a helper method to define mock.On call
//   - key string
//   - sd secret
//   - updateAccess bool
//   - cond conditionFn
func (_e *mockStore_Expecter) AddConditionally(key interface{}, sd interface{}, updateAccess interface{}, cond interface{}) *mockStore_AddConditionally_Call {
	return &mockStore_AddConditionally_Call{Call: _e.mock.On("AddConditionally", key, sd, updateAccess, cond)}
}

func (_c *mockStore_AddConditionally_Call) Run(run func(key string, sd secret, updateAccess bool, cond conditionFn)) *mockStore_AddConditionally_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(secret), args[2].(bool), args[3].(conditionFn))
	})
	return _c
}

func (_c *mockStore_AddConditionally_Call) Return() *mockStore_AddConditionally_Call {
	_c.Call.Return()
	return _c
}

func (_c *mockStore_AddConditionally_Call) RunAndReturn(run func(string, secret, bool, conditionFn)) *mockStore_AddConditionally_Call {
	_c.Run(run)
	return _c
}

// Get provides a mock function with given fields: key, updateAccess
func (_m *mockStore) Get(key string, updateAccess bool) (secret, bool) {
	ret := _m.Called(key, updateAccess)

	if len(ret) == 0 {
		panic("no return value specified for Get")
	}

	var r0 secret
	var r1 bool
	if rf, ok := ret.Get(0).(func(string, bool) (secret, bool)); ok {
		return rf(key, updateAccess)
	}
	if rf, ok := ret.Get(0).(func(string, bool) secret); ok {
		r0 = rf(key, updateAccess)
	} else {
		r0 = ret.Get(0).(secret)
	}

	if rf, ok := ret.Get(1).(func(string, bool) bool); ok {
		r1 = rf(key, updateAccess)
	} else {
		r1 = ret.Get(1).(bool)
	}

	return r0, r1
}

// mockStore_Get_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Get'
type mockStore_Get_Call struct {
	*mock.Call
}

// Get is a helper method to define mock.On call
//   - key string
//   - updateAccess bool
func (_e *mockStore_Expecter) Get(key interface{}, updateAccess interface{}) *mockStore_Get_Call {
	return &mockStore_Get_Call{Call: _e.mock.On("Get", key, updateAccess)}
}

func (_c *mockStore_Get_Call) Run(run func(key string, updateAccess bool)) *mockStore_Get_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(bool))
	})
	return _c
}

func (_c *mockStore_Get_Call) Return(_a0 secret, _a1 bool) *mockStore_Get_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *mockStore_Get_Call) RunAndReturn(run func(string, bool) (secret, bool)) *mockStore_Get_Call {
	_c.Call.Return(run)
	return _c
}

// List provides a mock function with no fields
func (_m *mockStore) List() []secret {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for List")
	}

	var r0 []secret
	if rf, ok := ret.Get(0).(func() []secret); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]secret)
		}
	}

	return r0
}

// mockStore_List_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'List'
type mockStore_List_Call struct {
	*mock.Call
}

// List is a helper method to define mock.On call
func (_e *mockStore_Expecter) List() *mockStore_List_Call {
	return &mockStore_List_Call{Call: _e.mock.On("List")}
}

func (_c *mockStore_List_Call) Run(run func()) *mockStore_List_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *mockStore_List_Call) Return(_a0 []secret) *mockStore_List_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockStore_List_Call) RunAndReturn(run func() []secret) *mockStore_List_Call {
	_c.Call.Return(run)
	return _c
}

// ListKeys provides a mock function with no fields
func (_m *mockStore) ListKeys() []string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for ListKeys")
	}

	var r0 []string
	if rf, ok := ret.Get(0).(func() []string); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	return r0
}

// mockStore_ListKeys_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListKeys'
type mockStore_ListKeys_Call struct {
	*mock.Call
}

// ListKeys is a helper method to define mock.On call
func (_e *mockStore_Expecter) ListKeys() *mockStore_ListKeys_Call {
	return &mockStore_ListKeys_Call{Call: _e.mock.On("ListKeys")}
}

func (_c *mockStore_ListKeys_Call) Run(run func()) *mockStore_ListKeys_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *mockStore_ListKeys_Call) Return(_a0 []string) *mockStore_ListKeys_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *mockStore_ListKeys_Call) RunAndReturn(run func() []string) *mockStore_ListKeys_Call {
	_c.Call.Return(run)
	return _c
}

// newMockStore creates a new instance of mockStore. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func newMockStore(t interface {
	mock.TestingT
	Cleanup(func())
}) *mockStore {
	mock := &mockStore{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
