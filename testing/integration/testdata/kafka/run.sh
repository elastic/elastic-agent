#!/bin/bash
# Starts a single-node KRaft Kafka broker for the Elastic Agent Kafka output
# integration tests. It runs inside the official apache/kafka image and mirrors
# the listeners and SASL/SSL setup of the beats Kafka test image
# (beats/testing/environments/docker/kafka), without building an image:
#   - 9092 INSIDE   PLAINTEXT, advertised as KAFKA_ADVERTISED_HOST (admin, healthcheck)
#   - 9094 OUTSIDE  PLAINTEXT, advertised as localhost (test consumers)
#   - 9093 SASL_SSL PLAIN / SCRAM-SHA-256 / SCRAM-SHA-512 / OAUTHBEARER, advertised as localhost
#     user "beats" / password "KafkaTest"; OAUTHBEARER uses Kafka's unsecured JWT validator
#     (test-only), tokens must carry a "sub" claim.
set -euo pipefail

KAFKA_HOME="${KAFKA_HOME:-/opt/kafka}"
KAFKA_ADVERTISED_HOST="${KAFKA_ADVERTISED_HOST:-kafka}"
KAFKA_CERTS_DIR="${KAFKA_CERTS_DIR:-/kafka-certs}"
KAFKA_LOGS_DIR="${KAFKA_LOGS_DIR:-/tmp/kraft-logs}"
CONFIG=/tmp/server.properties

cat >"${CONFIG}" <<PROPS
process.roles=broker,controller
node.id=1
controller.quorum.voters=1@localhost:9095
controller.listener.names=CONTROLLER
listeners=INSIDE://0.0.0.0:9092,OUTSIDE://0.0.0.0:9094,SASL_SSL://0.0.0.0:9093,CONTROLLER://0.0.0.0:9095
advertised.listeners=INSIDE://${KAFKA_ADVERTISED_HOST}:9092,OUTSIDE://localhost:9094,SASL_SSL://localhost:9093
listener.security.protocol.map=INSIDE:PLAINTEXT,OUTSIDE:PLAINTEXT,SASL_SSL:SASL_SSL,CONTROLLER:PLAINTEXT
inter.broker.listener.name=INSIDE
sasl.enabled.mechanisms=SCRAM-SHA-512,SCRAM-SHA-256,PLAIN,OAUTHBEARER
listener.name.sasl_ssl.scram-sha-512.sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required;
listener.name.sasl_ssl.scram-sha-256.sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required;
listener.name.sasl_ssl.plain.sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required user_beats="KafkaTest";
listener.name.sasl_ssl.oauthbearer.sasl.jaas.config=org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required unsecuredLoginStringClaim_sub="kafka" unsecuredValidatorPrincipalClaimName="sub" unsecuredValidatorAllowableClockSkewMs="5000";
ssl.keystore.location=${KAFKA_CERTS_DIR}/broker.keystore.jks
ssl.keystore.password=KafkaTest
ssl.truststore.location=${KAFKA_CERTS_DIR}/client.truststore.jks
ssl.truststore.password=KafkaTest
log.dirs=${KAFKA_LOGS_DIR}
log.flush.interval.ms=200
num.partitions=3
auto.leader.rebalance.enable=false
delete.topic.enable=true
offsets.topic.replication.factor=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
group.initial.rebalance.delay.ms=0
PROPS

echo "Formatting KRaft storage"
CLUSTER_ID="$("${KAFKA_HOME}/bin/kafka-storage.sh" random-uuid)"
"${KAFKA_HOME}/bin/kafka-storage.sh" format --ignore-formatted -t "${CLUSTER_ID}" -c "${CONFIG}" \
  --add-scram 'SCRAM-SHA-256=[name=beats,password=KafkaTest]' \
  --add-scram 'SCRAM-SHA-512=[name=beats,password=KafkaTest]'

echo "Starting Kafka broker"
exec "${KAFKA_HOME}/bin/kafka-server-start.sh" "${CONFIG}"
