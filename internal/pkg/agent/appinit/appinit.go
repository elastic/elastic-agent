// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package appinit

import (
	"sync"

	"github.com/elastic/elastic-agent-libs/service"
)

var stopSvcChan = make(chan bool)
var stopBeat = func() {
	close(stopSvcChan)
}

func init() {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		wg.Done()
		service.ProcessWindowsControlEvents(stopBeat)
	}()
	wg.Wait()
}

func StopSvcChan() chan bool {
	return stopSvcChan
}
