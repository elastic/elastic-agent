// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cli

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfirm(t *testing.T) {
	cases := map[string]struct {
		expectedResult bool
		expectedErr    string
	}{
		"y":    {true, ""},
		"y ":   {true, ""},
		" y":   {true, ""},
		"y\t":  {true, ""},
		"\ty":  {true, ""},
		"yes":  {true, ""},
		"yeah": {true, ""},
		"Y":    {true, ""},
		"YES":  {true, ""},
		"YEAH": {true, ""},
		"Yes":  {true, ""},
		"Yeah": {true, ""},
		"Yup":  {false, "error reading user input"},
		"n":    {false, ""},
		"n ":   {false, ""},
		" n":   {false, ""},
		"n\t":  {false, ""},
		"\tn":  {false, ""},
		"no":   {false, ""},
		"N":    {false, ""},
		"NO":   {false, ""},
		"No":   {false, ""},
		"nope": {false, "error reading user input"},
	}

	testFn := func(t *testing.T, input string, def, expectedResult bool, expectedErr string) {
		inputReader := strings.NewReader(input)
		var outWriter strings.Builder
		result, err := confirm(inputReader, &outWriter, "prompt", def)

		prompt := "prompt "
		if def {
			prompt += "[Y/n]:"
		} else {
			prompt += "[y/N]:"
		}

		require.Equal(t, expectedResult, result)
		if expectedErr == "" {
			require.NoError(t, err)
			require.Equal(t, prompt, outWriter.String())
		} else {
			expectedOut := prompt + "Please write 'y' or 'n'\n" + prompt
			require.Equal(t, expectedErr, err.Error())
			require.Equal(t, expectedOut, outWriter.String())
		}
	}

	for input, test := range cases {
		t.Run(input+"-default-to-yes", func(t *testing.T) {
			testFn(t, input, true, test.expectedResult, test.expectedErr)
		})
		t.Run(input+"-default-to-no", func(t *testing.T) {
			testFn(t, input, false, test.expectedResult, test.expectedErr)
		})
	}
}
