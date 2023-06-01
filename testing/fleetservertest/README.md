# Mock Fleet Server

It's mock for fleet-server allowing to test the Agent interactions with
fleet-server without the need of running a fleet-server and having full
control of it to test even edge cases such as error handling.

## tl;dr
### See [`fleetservertest_test.go`](fleetserver_test.go) for examples

### `fleetservertest.API` defines a `handlernameFn` property for each available handlers. By default, any not implemented handler returns a `http.StatusNotImplemented`
### Use `fleetservertest.NewServer(fleetservertest.API{})` to create a new test server. It's a `*httptest.Server`.

```go
	NewServer(API{
		AckFn:            nil,
		CheckinFn:        nil,
		EnrollFn:         nil,
		ArtifactFn:       nil,
		StatusFn:         nil,
		UploadBeginFn:    nil,
		UploadChunkFn:    nil,
		UploadCompleteFn: nil,
	})
```


### Use the `fleetservertest.NewPATHNAME(args)` functions to get the path ready to be used:
```go
p := NewPathAgentAcks("my-agent-id")
// p = "/api/fleet/agents/my-agent-id/acks"
```

### Use `fleetservertest.NewHANDERNAME()` to get a ready to use handler:
```go
ts := fleetservertest.NewServer(API{
	CheckinFn: fleetservertest.NewCheckinHandler("agentID", "ackToken", false),
})
```

### Check [`handlers.go`](handlers.go) for the available paths and handlers.
### Check [`models.go`](models.go) for the request and response models or the [openapi](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/elastic/fleet-server/main/model/openapi.yml#/) definition.
