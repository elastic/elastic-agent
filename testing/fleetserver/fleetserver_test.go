package fleetserver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"testing"

	"github.com/elastic/elastic-agent/testing/fleetserver/openapi"
)

func TestNewTest(t *testing.T) {
	ts := NewTest(&API{
		StatusFn: func(_ context.Context, xRequestID string) (openapi.StatusResponse, *openapi.ModelError) {
			return openapi.StatusResponse{}, nil
		},
	})

	resp, err := http.Get(ts.URL + "/api/status")
	if err != nil {
		panic(err)
	}

	bs, _ := httputil.DumpResponse(resp, true)

	fmt.Printf("%s", bs)
}
