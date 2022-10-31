# Runtime documentation


## Service runtime

This part of the documentation describes how the Agent ```service runtime``` works. The design is not new and was inherited from V1, just was not documented anywhere.

The service runtime is currently used to support integration with the Endpoint service and is very much customized to the expected behavior of the service. The Endpoint service can not be stopped (protected on windows) and the Agent runtime component is not expected to manage the lifetime of the service. The Endpoint service is expected to be always running.

In order for the Endpoint to connect to the Agent, the Agent starts up the gRPC "connection info" server on the local port specified in the endpoint specification file. The "connection info" service sends the connection parameters/credentials to the agent upon the connection, the Endpoint uses to establish primary connection to the Agent

The following are the steps the Endpoint goes through to establish the connection to the Agent:
1. The Endpoint connects to the "connection info" local port
2. The Agent sends the connection parameters/credentials to the Endpoint and closes the connection
3. The Endpoint establishes the primary connection to the Agent

The Agent can only call 3 commands on the endpoint binary that allows it to:
1. Check if the Endpoint service is installed
2. Install the Endpoint service. The Endpoint service is started automatically upon installation.
3. Uninstall the Endpoint service.


The Agent is expected to send ```STOPPING``` state to the Endpoint if possible. This helps to ```deactivate``` the Endpoint in the k8s environment for example.

When the Endpoint is removed from the policy the Endpoint is uninstalled by the Agent as follows:
1. If the Endpoint has never checked in the Agent waits with the timeout for the first check-in
2. The Agent sends ```STOPPING``` state to the Endpoint
3. The Agent calls uninstall command based on the service specification