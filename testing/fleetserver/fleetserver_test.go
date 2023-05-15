package fleetserver

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

func ExampleNewTest() {
	ts := NewTest(API{
		StatusFn: func(ctx context.Context) (*StatusResponse, *HTTPError) {
			return &StatusResponse{
				Name:   "fleet-server-test-api",
				Status: "it works!",
				Version: StatusResponseVersion{
					Number:    "1",
					BuildHash: "aHash",
					BuildTime: "now",
				},
			}, nil
		}})

	resp, err := http.Get(ts.URL + "/api/status")
	if err != nil {
		panic(fmt.Sprintf("could not make request to fleet-test-server: %v", err))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if err != nil {
			panic(fmt.Sprintf("could not read response: %v", err))
		}
	}
	fmt.Printf("%s", body)

	// Output:
	// {"name":"fleet-server-test-api","status":"it works!","version":{"number":"1","build_hash":"aHash","build_time":"now"}}
}
