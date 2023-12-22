// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteMarkerFileWithTruncation(t *testing.T) {
	tmpDir := t.TempDir()
	testMarkerFile := filepath.Join(tmpDir, markerFilename)

	// Write a long marker file
	err := writeMarkerFileCommon(testMarkerFile, randomBytes(40), true)
	require.NoError(t, err)

	// Get length of file
	fileInfo, err := os.Stat(testMarkerFile)
	require.NoError(t, err)
	originalSize := fileInfo.Size()

	// Write a shorter marker file
	err = writeMarkerFileCommon(testMarkerFile, randomBytes(25), true)
	require.NoError(t, err)

	// Get length of file
	fileInfo, err = os.Stat(testMarkerFile)
	require.NoError(t, err)
	newSize := fileInfo.Size()

	// Make sure shorter file has is smaller in length than
	// the original long marker file
	require.Less(t, newSize, originalSize)
}

func randomBytes(length int) []byte {
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZÅÄÖ" +
		"abcdefghijklmnopqrstuvwxyzåäö" +
		"0123456789" +
		"~=+%^*/()[]{}/!@#$?|")

	var b []byte
	for i := 0; i < length; i++ {
		rune := chars[rand.Intn(len(chars))]
		b = append(b, byte(rune))
	}

	return b
}
