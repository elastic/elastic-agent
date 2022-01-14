// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package composed

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/program"
	"github.com/elastic/elastic-agent-poc/internal/pkg/artifact/download"
)

type FailingDownloader struct {
	called bool
}

func (d *FailingDownloader) Download(ctx context.Context, _ program.Spec, _ string) (string, error) {
	d.called = true
	return "", errors.New("failing")
}

func (d *FailingDownloader) Called() bool { return d.called }

type SuccDownloader struct {
	called bool
}

func (d *SuccDownloader) Download(ctx context.Context, _ program.Spec, _ string) (string, error) {
	d.called = true
	return "succ", nil
}
func (d *SuccDownloader) Called() bool { return d.called }

func TestComposed(t *testing.T) {
	testCases := []testCase{
		{
			downloaders:    []CheckableDownloader{&FailingDownloader{}, &SuccDownloader{}},
			checkFunc:      func(d []CheckableDownloader) bool { return d[0].Called() && d[1].Called() },
			expectedResult: true,
		}, {
			downloaders:    []CheckableDownloader{&SuccDownloader{}, &SuccDownloader{}},
			checkFunc:      func(d []CheckableDownloader) bool { return d[0].Called() && !d[1].Called() },
			expectedResult: true,
		}, {
			downloaders:    []CheckableDownloader{&SuccDownloader{}, &FailingDownloader{}},
			checkFunc:      func(d []CheckableDownloader) bool { return d[0].Called() && !d[1].Called() },
			expectedResult: true,
		}, {
			downloaders:    []CheckableDownloader{&FailingDownloader{}, &FailingDownloader{}},
			checkFunc:      func(d []CheckableDownloader) bool { return d[0].Called() && d[1].Called() },
			expectedResult: false,
		},
	}

	for _, tc := range testCases {
		d := NewDownloader(tc.downloaders[0], tc.downloaders[1])
		r, _ := d.Download(context.TODO(), program.Spec{Name: "a", Cmd: "a", Artifact: "a/a"}, "b")

		assert.Equal(t, tc.expectedResult, r == "succ")

		assert.True(t, tc.checkFunc(tc.downloaders))
	}
}

type CheckableDownloader interface {
	download.Downloader
	Called() bool
}

type testCase struct {
	downloaders    []CheckableDownloader
	checkFunc      func(downloaders []CheckableDownloader) bool
	expectedResult bool
}
