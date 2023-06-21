# Mock Fleet Server

It's mock for fleet-server allowing to test the Agent interactions with
fleet-server without the need of running a fleet-server and having full
control of it to test even edge cases such as error handling.

## tl;dr

- See [`fleetservertest_test.go`](fleetserver_test.go) for examples.

- `fleetservertest.API` defines a `handlernameFn` property for each available handlers. By default, any not implemented handler returns a `http.StatusNotImplemented`.

- Use `fleetservertest.NewServer(fleetservertest.API{})` to create a new test server. It's a `*httptest.Server`:

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

- Use the `fleetservertest.NewPATHNAME(args)` functions to get a path ready to be used:
```go
p := NewPathAgentAcks("my-agent-id")
// p = "/api/fleet/agents/my-agent-id/acks"
```

- Use `fleetservertest.NewHANDERNAME()` to get a ready to use handler:
```go
ts := fleetservertest.NewServer(API{
	CheckinFn: fleetservertest.NewCheckinHandler("agentID", "ackToken", false),
})
```

- Check [`handlers.go`](handlers.go) for the available paths and handlers.
- Check [`models.go`](models.go) for the request and response models or the [openapi](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/elastic/fleet-server/main/model/openapi.yml#/) definition.

---------------------------------------------------------

# Mock Fleet Server

Use cases:

### test single agent <-> fleet-serve interactions: Done
A single fleet-server handler involved.
#### Minimal requirements:
 - easy to implement fleet-server handler
 - run it as a valid HTTP server
Nice  have: New Handler functions taking  a few options to tailor the handler for
each test. Some of it done.

### Run the agent against the mock fleet-server
Allow to e2e test the Agent without using a real fleet-server which allows:
 - test error cases / unhappy paths / hard to reproduce states. Eg. fleet-server sends an invalid policy
 - develop and test features before they're fully implemented on fleet-server

in order run the agent against the mock fleet-server, it needs to:
 - have at least the states, enroll, checkin and ack handlers implemented
 - an API key and Enrollment token for authentication. Which need to be shared with the test
   - the ES API key needs to be valid if, and only if a real component is used with the agent
 - integrations to add in the policy:
   - fake component
   - fake shipper
   - Should it allow a real components/integration to be used?
     - system Integration (?)
     - endpoint-security (?)

### Open Questions
- How integrate well with the test framework?
  - how get the ES endpoint and credential. Right now it isn't exposed.
- Should the mock fleet-server allow any other components besides the fake inout and shipper?
  - using fake components avoids the need for a real ES/output
- allow to enrol more than one agent?
  - more than 1 agent -> more state do manage. Do we need this?
