#!/bin/bash
# Reports healthy once the broker can create and delete a topic.
set -euo pipefail
KAFKA_HOME="${KAFKA_HOME:-/opt/kafka}"
TOPIC="healthcheck-$(date '+%s-%N')"
"${KAFKA_HOME}/bin/kafka-topics.sh" --bootstrap-server localhost:9092 --create --partitions 1 --replication-factor 1 --topic "${TOPIC}" >/dev/null
"${KAFKA_HOME}/bin/kafka-topics.sh" --bootstrap-server localhost:9092 --delete --topic "${TOPIC}" >/dev/null
