// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

var name string

func main() {
	if len(os.Args) == 1 {
		log.Println("Usage: ./testsignal [name]")
		os.Exit(1)
	}

	name = os.Args[1]
	log.Printf("[%s] Starting, PID %d", name, os.Getpid())
	defer log.Printf("[%s] Done", name)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)

	log.Printf("[%s] Wait for signal", name)
	s := <-signals
	log.Printf("[%s] Got signal: %s", name, s)
}
