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
