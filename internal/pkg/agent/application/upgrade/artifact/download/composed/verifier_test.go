// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package composed

import (
	"errors"
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	agtversion "github.com/elastic/elastic-agent/pkg/version"

	"github.com/stretchr/testify/assert"
)

type ErrorVerifier struct {
	called bool
}

func (d *ErrorVerifier) Name() string {
	return "error"
}

func (d *ErrorVerifier) Verify(artifact.Artifact, agtversion.ParsedSemVer, bool, ...string) error {
	d.called = true
	return errors.New("failing")
}

func (d *ErrorVerifier) Called() bool { return d.called }

type FailVerifier struct {
	called bool
}

func (d *FailVerifier) Name() string {
	return "fail"
}

func (d *FailVerifier) Verify(artifact.Artifact, agtversion.ParsedSemVer, bool, ...string) error {
	d.called = true
	return &download.InvalidSignatureError{File: "", Err: errors.New("invalid signature")}
}

func (d *FailVerifier) Called() bool { return d.called }

type SuccVerifier struct {
	called bool
}

func (d *SuccVerifier) Name() string {
	return "succ"
}

func (d *SuccVerifier) Verify(artifact.Artifact, agtversion.ParsedSemVer, bool, ...string) error {
	d.called = true
	return nil
}

func (d *SuccVerifier) Called() bool { return d.called }

func TestVerifier(t *testing.T) {
	log, _ := logger.New("", false)
	testCases := []verifyTestCase{
		{
			verifiers:      []CheckableVerifier{&ErrorVerifier{}, &SuccVerifier{}, &FailVerifier{}},
			checkFunc:      func(d []CheckableVerifier) bool { return d[0].Called() && d[1].Called() && !d[2].Called() },
			expectedResult: true,
		}, {
			verifiers:      []CheckableVerifier{&SuccVerifier{}, &ErrorVerifier{}, &FailVerifier{}},
			checkFunc:      func(d []CheckableVerifier) bool { return d[0].Called() && !d[1].Called() && !d[2].Called() },
			expectedResult: true,
		}, {
			verifiers:      []CheckableVerifier{&FailVerifier{}, &ErrorVerifier{}, &SuccVerifier{}},
			checkFunc:      func(d []CheckableVerifier) bool { return d[0].Called() && d[1].Called() && d[2].Called() },
			expectedResult: true,
		}, {
			verifiers:      []CheckableVerifier{&ErrorVerifier{}, &FailVerifier{}, &SuccVerifier{}},
			checkFunc:      func(d []CheckableVerifier) bool { return d[0].Called() && d[1].Called() && d[2].Called() },
			expectedResult: true,
		}, {
			verifiers:      []CheckableVerifier{&ErrorVerifier{}, &ErrorVerifier{}, &FailVerifier{}},
			checkFunc:      func(d []CheckableVerifier) bool { return d[0].Called() && d[1].Called() && d[2].Called() },
			expectedResult: false,
		},
	}

	testVersion := agtversion.NewParsedSemVer(1, 2, 3, "", "")
	for _, tc := range testCases {
		d := NewVerifier(log, tc.verifiers[0], tc.verifiers[1], tc.verifiers[2])
		err := d.Verify(artifact.Artifact{Name: "a", Cmd: "a", Artifact: "a/a"}, *testVersion, false)

		assert.Equal(t, tc.expectedResult, err == nil)

		assert.True(t, tc.checkFunc(tc.verifiers))
	}
}

type CheckableVerifier interface {
	download.Verifier
	Called() bool
}

type verifyTestCase struct {
	verifiers      []CheckableVerifier
	checkFunc      func(verifiers []CheckableVerifier) bool
	expectedResult bool
}
