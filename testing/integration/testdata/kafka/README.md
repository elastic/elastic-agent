# Kafka test broker fixture

Used by the Kafka output integration tests in `testing/integration/ess/otel_test.go`
(see `kafkaComposeContent`). The tests run the official `apache/kafka` image with these
files mounted in instead of building the beats Kafka image
(`beats/testing/environments/docker/kafka`) from source, which took about 10 minutes
on a fresh CI worker.

- `run.sh`: starts a single-node KRaft broker that mirrors the beats image's listeners:
  `9092` INSIDE (plaintext, advertised as `KAFKA_ADVERTISED_HOST`), `9094` OUTSIDE
  (plaintext, advertised as `localhost`) and `9093` SASL_SSL (PLAIN, SCRAM-SHA-256,
  SCRAM-SHA-512 and OAUTHBEARER, advertised as `localhost`). Username/password
  mechanisms use user `beats` with password `KafkaTest`; OAUTHBEARER uses Kafka's
  unsecured JWT validator (test only), so tokens only need a `sub` claim. Topics are
  created with 3 partitions.
- `healthcheck.sh`: reports healthy once a topic can be created and deleted.
- `certs/`: the broker keystore, the client truststore and the CA certificate, copied
  from `beats/testing/environments/docker/kafka/certs` (see the README there for how
  they were generated; the CA is valid until 2036).
