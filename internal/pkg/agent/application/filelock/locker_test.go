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

package filelock

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testLockFile = "test.lock"

func TestAppLocker(t *testing.T) {
	tmp, _ := ioutil.TempDir("", "locker")
	defer os.RemoveAll(tmp)

	locker1 := NewAppLocker(tmp, testLockFile)
	locker2 := NewAppLocker(tmp, testLockFile)

	require.NoError(t, locker1.TryLock())
	assert.Error(t, locker2.TryLock())
	require.NoError(t, locker1.Unlock())
	require.NoError(t, locker2.TryLock())
	assert.Error(t, locker1.TryLock())
	require.NoError(t, locker2.Unlock())
}
