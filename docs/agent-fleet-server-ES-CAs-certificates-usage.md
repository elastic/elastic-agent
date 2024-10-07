# TLS between Elastic AGent <-> Fleet Server <-> Elasticsearch

This shows the different certificates and certificate authorities used by the Elastic Agent, Fleet Server and Elasticsearch for the control plane communication and their respective cli flags when installing the Elastic Agent.

 - Elastic Agent (client) makes HTTPS requests to Fleet Server (server)
 - Fleet Server (client) makes HTTPS requests to Elasticsearch (server)

## TLS

For the TLS case, the following is used:
 - fleet-ca: the certificate authority for the certificate presented by Fleet Server
 - fleet-cert: the TLS certificate Fleet Server presents when a client makes an HTTPS request
 - fleet-cert-key: the private key for Fleet Server's TLS certificate (not shown in the diagram)
 - es-ca: the certificate authority for the certificate presented by Elasticsearch

```shell
elastic-agent install --url=https://your-fleet-server.elastic.co:443 \
--certificate-authorities=/path/to/fleet-ca \
--fleet-server-es=https://es.elastic.com:443 \
--fleet-server-es-ca=/path/to/es-ca \
--fleet-server-cert=/path/to/fleet-cert \
--fleet-server-cert-key=/path/to/fleet-cert-key \
--fleet-server-service-token=FLEET-SERVER-SERVICE-TOKEN \
--fleet-server-policy=FLEET-SERVER-POLICY-ID \
--fleet-server-port=8220
```
```mermaid
flowchart LR
    subgraph TLS
        elastic-agent
        fleet-server
        elasticsearch
    end


    fleet-server --> |**fleet-server: presents fleet-cert**
      --fleet-server-cert=fleet-cert| elastic-agent

    elastic-agent --> |**agent validates fleet-ca:**
      --certificate-authorities=/path/to/fleet-ca| fleet-server

    fleet-server --> | **fleet-server es-ca validates es-cert:**
      --fleet-server-es-ca=es-ca| elasticsearch

        elasticsearch --> | **elasticsearch presents es-cert**| fleet-server


    subgraph elasticsearch
        es-cert
    end
    subgraph fleet-server
        fleet-cert
        es-ca
    end
    subgraph elastic-agent
        fleet-ca
    end
```

## mTLS

For the mTLS case, the following is used:
- agent-ca: the certificate authority for the certificate presented by the Elastic Agent
- agent-cert: the client TLS certificate Elastic Agent presents to Fleet Server
- agent-cert-key: the private key for the Elastic Agent's TLS certificate (not shown in the diagram)

- fleet-ca: the certificate authority for the certificate presented by Fleet Server
- fleet-cert: the TLS certificate Fleet Server presents when a client makes an HTTPS request
- fleet-cert-key: the private key for Fleet Server's TLS certificate (not shown in the diagram)

- fleet-es-ca: the certificate authority for the client TLS certificate presented by Fleet Server to Elasticsearch
- fleet-es-cert: the client TLS certificate Fleet Server presents to Elasticsearch
- fleet-es-cert-key: the private key for Fleet Server's client TLS certificate (not shown in the diagram)

- es-ca: the certificate authority for the certificate presented by Elasticsearch
- es-cert: the TLS certificate Elasticsearch presents when a client makes an HTTPS request

```shell
elastic-agent install --url=https://your-fleet-server.elastic.co:443 \
--certificate-authorities=/path/to/fleet-ca,/path/to/agent-ca \
--elastic-agent-cert=/path/to/agent-cert \
--elastic-agent-cert-key=/path/to/agent-cert-key \
--fleet-server-es=https://es.elastic.com:443 \
--fleet-server-es-ca=/path/to/es-ca \
--fleet-server-es-cert=/path/to/fleet-es-cert \
--fleet-server-es-cert-key=/path/to/fleet-es-cert-key \
--fleet-server-cert=/path/to/fleet-cert \
--fleet-server-cert-key=/path/to/fleet-cert-key \
--fleet-server-client-auth=required \
--fleet-server-service-token=FLEET-SERVER-SERVICE-TOKEN \
--fleet-server-policy=FLEET-SERVER-POLICY-ID \
--fleet-server-port=8220
```
```mermaid
flowchart LR
    subgraph mTLS
        elastic-agent((elastic-agent))

        fleet-server((fleet-server))
        elasticsearch((elasticsearch))

    end


    elastic-agent --> |**agent: fleet-ca validates fleet-cert:**
      --certificate-authorities=/path/to/fleet-ca| fleet-server

    elastic-agent --> |**agent presents agent-cert:**
      --elastic-agent-cert=agent-cert| fleet-server


    fleet-server --> |**fleet-server: presents fleet-cert**
      --fleet-server-cert=fleet-cert| elastic-agent

    fleet-server --> |**fleet-server: agent-ca validates agent-cert**
      --certificate-authorities=fleet-ca,agent-ca| elastic-agent


    fleet-server --> | **fleet-server es-ca validates es-cert:**
      --fleet-server-es-ca=es-ca| elasticsearch

    fleet-server --> | **fleet-server presents fleet-es-cert:**
      --fleet-server-es-cert=fleet-es-cert| elasticsearch


    elasticsearch --> | **elasticsearch presents es-cert**| fleet-server
    elasticsearch --> | **elasticsearch: fleet-es-ca validates fleet-es-cert**| fleet-server


    subgraph elastic-agent
        fleet-ca
        agent-cert
    end
    subgraph fleet-server
        fleet-cert
        fleet-es-cert
        agent-ca
        es-ca
    end
    subgraph elasticsearch
        es-cert
        fleet-es-ca
    end
```


