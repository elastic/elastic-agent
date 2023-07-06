# Mock Fleet Server

It's a mock for fleet-server, allowing testing of Agent interactions with
fleet-server without the need to run a fleet-server and have full control over
it, to even test edge cases such as error handling.

The server is designed to work with one single agent. The Agent either needs to
be enrolled or AgentID must be set on Handlers. Use `WithAgentID` to set it when
creating the server. Also, the requests are executed sequentially, making safe for
the handlers implementations to access and eventually change the Handlers properties.

Right now there is no authentication, which means any enrollment token will work
by default. There is some work done for authentication on [auth.go](auth.go).

## tl;dr

- See [`fleetservertest_test.go`](fleetserver_test.go) for examples.

- on `fleetservertest.Handlers` the `handlernameFn` properties are used for
- implementing the handlers.By default, any not implemented handler returns a
- `http.StatusNotImplemented`.

- Use `fleetservertest.NewServer(fleetservertest.Handlers{})` to create a new
- test server. It's a `*httptest.Server`:

```go
	NewServer(&Handlers{
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

- Use the `fleetservertest.NewPATHNAME(args)` functions to get a path ready to be used:
```go
p := NewPathAgentAcks("my-agent-id")
// p = "/api/fleet/agents/my-agent-id/acks"
```

- Use `fleetservertest.NewHANDERNAME()` to get a ready to use handler:
```go
ts := fleetservertest.NewServer(&Handlers{
	CheckinFn: fleetservertest.NewHandlerStatusHealth(),
})
```

- Check [`fleetserver_test.go`](fleetserver_test.go) for examples.
- Check [`handlers.go`](handlers.go) for the available paths and handlers.
- Check [`models.go`](models.go) for the request and response models or the [openapi](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/elastic/fleet-server/main/model/openapi.yml#/) definition.
