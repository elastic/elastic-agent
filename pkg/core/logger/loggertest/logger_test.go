// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package loggertest

import "fmt"

func ExamplePrintObservedLogs() {
	logger, obs := New("testLogger")

	logger.Debug("a debug message")
	logger.Debugw("a debug message with keys", "key2", 42)
	logger.Infow("an info message")
	logger.Infow("an info message with keys", "key1", "value1")
	logger.Warn("a warn message")
	logger.Warnw("a warn message with keys", "key2", 42)
	logger.Error("an error message")
	logger.Errorw("an error message with keys", "key1", "value1")

	printFn := func(a ...any) { fmt.Println(a...) }

	PrintObservedLogs(obs.TakeAll(), printFn)

	// Output:
	// [debug] a debug message
	// [debug] a debug message with keys key2=42
	// [info] an info message
	// [info] an info message with keys key1=value1
	// [warn] a warn message
	// [warn] a warn message with keys key2=42
	// [error] an error message
	// [error] an error message with keys key1=value1
}
