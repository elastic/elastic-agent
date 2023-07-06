package proxytest

import (
	"fmt"
	"sync"
	"testing"
)

func TestProxy(t *testing.T) {
	p := New()
	fmt.Println("listening on:", p.URL)

	wg := sync.WaitGroup{}
	wg.Add(1)
	wg.Wait()
}
