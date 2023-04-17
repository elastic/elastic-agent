// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package uploader

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockBackoff struct {
	mock.Mock
}

func (m *mockBackoff) Wait() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *mockBackoff) NextWait() time.Duration {
	args := m.Called()
	return args.Get(0).(time.Duration)
}

func (m *mockBackoff) Reset() {
	m.Called()
}

type mockSender struct {
	mock.Mock
}

func (m *mockSender) Send(ctx context.Context, method, path string, params url.Values, headers http.Header, body io.Reader) (*http.Response, error) {
	args := m.Called(ctx, method, path, params, headers, body)
	return args.Get(0).(*http.Response), args.Error(1)
}

func (m *mockSender) URI() string {
	args := m.Called()
	return args.String(0)
}

func (m *mockSender) Timeout() time.Duration {
	args := m.Called()
	return args.Get(0).(time.Duration)
}

func Test_retrySender_Send(t *testing.T) {
	tests := []struct {
		name   string
		sender func() *mockSender
		status int
		err    error
	}{{
		name: "200 return",
		sender: func() *mockSender {
			m := &mockSender{}
			m.On("Send", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&http.Response{StatusCode: 200}, nil).Once()
			return m
		},
		status: 200,
		err:    nil,
	}, {
		name: "429 retries",
		sender: func() *mockSender {
			m := &mockSender{}
			m.On("Send", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&http.Response{StatusCode: 429}, nil).Once()
			m.On("Send", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&http.Response{StatusCode: 200}, nil).Once()
			return m
		},
		status: 200,
		err:    nil,
	}, {
		name: "too many retries",
		sender: func() *mockSender {
			m := &mockSender{}
			m.On("Send", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&http.Response{StatusCode: 429}, nil).Times(3)
			return m
		},
		status: 429,
		err:    nil,
	}, {
		name: "503 return",
		sender: func() *mockSender {
			m := &mockSender{}
			m.On("Send", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&http.Response{StatusCode: 503}, nil).Once()
			return m
		},
		status: 503,
		err:    nil,
	}, {
		name: "context error",
		sender: func() *mockSender {
			m := &mockSender{}
			m.On("Send", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&http.Response{}, context.Canceled).Once()
			return m
		},
		status: 0,
		err:    context.Canceled,
	}, {
		name: "non-context error will retry",
		sender: func() *mockSender {
			m := &mockSender{}
			m.On("Send", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&http.Response{}, errors.New("oh no")).Once()
			m.On("Send", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&http.Response{StatusCode: 200}, nil).Once()
			return m
		},
		status: 200,
		err:    nil,
	}}

	backoff := &mockBackoff{}
	backoff.On("Reset").Return()
	backoff.On("Wait").Return(true)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sender := tc.sender()
			c := &retrySender{
				c:    sender,
				max:  3,
				wait: backoff,
			}
			resp, err := c.Send(context.Background(), "POST", "/", nil, nil, bytes.NewReader([]byte("abcd")))
			defer func() {
				if resp.Body != nil {
					_ = resp.Body.Close()
				}

			}()
			if err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.Equal(t, tc.err, err)
				assert.Equal(t, tc.status, resp.StatusCode)
			}
			sender.AssertExpectations(t)
		})
	}
}

// This test validates that the body that is sent on a reattempt is the same as the original
func Test_retrySender_bodyValidation(t *testing.T) {
	var body1, body2 []byte
	var err error
	sender := &mockSender{}
	sender.On("Send", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		r := args.Get(5).(io.Reader)
		body1, err = io.ReadAll(r)
		require.NoError(t, err)
	}).Return(&http.Response{StatusCode: 429}, nil).Once()
	sender.On("Send", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		r := args.Get(5).(io.Reader)
		body2, err = io.ReadAll(r)
		require.NoError(t, err)
	}).Return(&http.Response{StatusCode: 200}, nil).Once()

	backoff := &mockBackoff{}
	backoff.On("Reset").Return()
	backoff.On("Wait").Return(true)

	c := &retrySender{
		c:    sender,
		max:  3,
		wait: backoff,
	}
	resp, err := c.Send(context.Background(), "POST", "/", nil, nil, bytes.NewReader([]byte("abcd")))
	defer func() {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()
	require.NoError(t, err)
	assert.Equal(t, resp.StatusCode, 200)
	assert.Equal(t, []byte("abcd"), body1)
	assert.Equal(t, []byte("abcd"), body2)
	sender.AssertExpectations(t)
}

func Test_Client_UploadDiagnostics(t *testing.T) {
	var chunk0, chunk1, chunk2 []byte
	var err error
	sender := &mockSender{}
	sender.On("Send", mock.Anything, "POST", PathNewUpload, mock.Anything, mock.Anything, mock.Anything).Return(&http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewReader([]byte(`{"upload_id":"test-upload","chunk_size":2}`))),
	}, nil).Once()

	// Validate that the Chunk endpoint is called 3 times, and that the chunks are uploaded as expected.
	sender.On("Send", mock.Anything, "PUT", fmt.Sprintf(PathChunk, "test-upload", 0), mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		r := args.Get(5).(io.Reader)
		chunk0, err = io.ReadAll(r)
		require.NoError(t, err)
	}).Return(&http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewReader(nil)),
	}, nil).Once()
	sender.On("Send", mock.Anything, "PUT", fmt.Sprintf(PathChunk, "test-upload", 1), mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		r := args.Get(5).(io.Reader)
		chunk1, err = io.ReadAll(r)
		require.NoError(t, err)
	}).Return(&http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewReader(nil)),
	}, nil).Once()
	sender.On("Send", mock.Anything, "PUT", fmt.Sprintf(PathChunk, "test-upload", 2), mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		r := args.Get(5).(io.Reader)
		chunk2, err = io.ReadAll(r)
		require.NoError(t, err)
	}).Return(&http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewReader(nil)),
	}, nil).Once()

	sender.On("Send", mock.Anything, "POST", fmt.Sprintf(PathFinishUpload, "test-upload"), mock.Anything, mock.Anything, mock.Anything).Return(&http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewReader(nil)),
	}, nil).Once()

	c := &Client{
		c:       sender,
		agentID: "test-agent",
	}
	id, err := c.UploadDiagnostics(context.Background(), "test-id", "2023-01-30T09-40-02Z-00", 5, bytes.NewBufferString("abcde"))
	require.NoError(t, err)
	assert.Equal(t, "test-upload", id)
	assert.Equal(t, "ab", string(chunk0))
	assert.Equal(t, "cd", string(chunk1))
	assert.Equal(t, "e", string(chunk2))
	sender.AssertExpectations(t)
}
