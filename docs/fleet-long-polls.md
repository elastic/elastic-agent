# Fleet long polls

In order to improve scalability of elastic agent deployments managed by Fleet, the agent will perform long-running check-in request (that is, the fleet gateway will wait longer for a check-in response)


## Before
Before this change, the fleet gateway would use a timeout of 10 minutes, with the expectation for fleet server to control the long poll and respond within 5 minutes.

In case of transient errors we have an exponential backoff retry mechanism until we manage to complete a check-in

The fleet gateway would then wait for a second after a successful check-in before initiating a new check-in with the new agent state.

## After
Fleet Gateway now will perform a check-in with the same frequency as before, waiting up to 12 minutes before timing out (we plan to increase this duration in future versions to ~30 minutes).
The duration increase would increase the probability of fleet keeping stale state information about the agent.

In order to keep a reasonably updated state on fleet, the fleet gateway now performs the check-in asynchronously while listening for agent state changes: if the agent state changes from the one we used for the ongoing check-in, after the configured debounce time (default: 5 minutes) Fleet Gateway will cancel the current request and launch a new check-in to Fleet with the updated information.

The backoff mechanism for transient errors is still in place but now it will stop retrying if the ongoing check-in has been explicitly canceled.

### Implementation details

#### To cancel or not to cancel?
When Fleet Gateway receives a tick from the scheduler, it will trigger a check-in (see `FleetGateway.triggerCheckin()`):

- creates a subcontext from the main Fleet Gateway context and uses it to subscribe to state updates from Coordinator (abstracted away as a StateFetcher interface)
- it uses the first state to initiate a cancellable check-in (see `FleetGateway.performCancellableCheckin()` for details)
- the cancellable check-in is implemented as an infinite loop where we continuosly listen for:
  - main context expiration (meaning Fleet Gateway is shutting down) so we return immediately, canceling the check-in on our way out
  - a result from the check-in we initiated (sent on a channel by `FleetGateway.doExecuteAsync()`)
  - a state change from coordinator that impacts the state of the agent sent with the check-in

If the ongoing check-in completes successfully, we return the response without any errors and the check-in response is processed as usual (Actions will get extrated from it and dispatched)

If we detect a state change coming from the coordinator subscription that differs from what was sent in the ongoing check-in:
  - we cancel the ongoing check-in and try to reap the result (we give up after 1 second)
  - we return a specific `needNewCheckinError` error that contains the new state to be used for the new check-in attempt

### Avoid flooding fleet server
In order to have a minimum interval between consecutive check-in attempts a debounce function is passed to Fleet Gateway.
The code for the debouncer can be found in (debounce.go)[../internal/pkg/application/agent/]

The debouncer will keep consuming values for at least the debounce time and will output the last received value (or not at all if no value comes though the `in` channel).

This mechanism will ensure that we don't cancel and retrigger checkins too quickly even when the agent state changes frequently.

### Configuration
Timeout setting for the http client is read from `fleet.timeout` key in configuration expressed as a time duration string.

Here's an example of a partial config
```yaml
fleet:
  timeout: 12m0s
```

Due to the way that configuration for fleet-managed agents is handled, it is not currently possible to change such values from whatever the default values were when the agent has been enrolled. For this reason the fleet gateway debounce,interval and backoff settings contained in `FleetGatewaySettings` struct has not been included in the overall `FleetAgentConfig` struct.