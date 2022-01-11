package mage

import (
	"testing"

	"github.com/stretchr/testify/assert"
)


func TestGetVersion(t *testing.T) {
	bp, err := BeatQualifiedVersion()
	assert.NoError(t, err)
	_= bp
}
