#!/bin/bash
#### 
# Bash Script that creates the needed https://github.com/elastic/kibana/blob/main/x-pack/plugins/fleet/server/services/elastic_agent_manifest.ts
# The script takes as an argument the path of elastic-agent manifests
# Eg. ./creator_k8s_manifest.sh deploy/kubernetes
####


STANDALONE=elastic-agent-standalone-kubernetes-without-configmap.yaml
MANAGED=elastic-agent-managed-kubernetes-without-configmap.yaml
OUTPUT_FILE=elastic_agent_manifest.ts

#Check if arguments provided
((!$#)) && echo "No arguments provided!Please provide path of elastic-agent files" && exit 1
MANIFEST_PATH=$1

#Check if file elastic-agent-standalone-kubernetes-without-configmap.yaml exists
if [ ! -f "$MANIFEST_PATH/$STANDALONE" ]; then
    echo "$MANIFEST_PATH/$STANDALONE does not exists"
    exit 1
fi

#Check if file elastic-agent-managed-kubernetes-without-configmap.yaml exists
if [ ! -f "$MANIFEST_PATH/$MANAGED" ]; then
    echo "$MANIFEST_PATH/$MANAGED does not exists"
    exit 1
fi

#Start creation of output file
cat << EOF > $OUTPUT_FILE
/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
 
export const elasticAgentStandaloneManifest = \`---
EOF

cat $MANIFEST_PATH/$STANDALONE >> $OUTPUT_FILE
echo "\`;" >> $OUTPUT_FILE

cat << EOF >> $OUTPUT_FILE

export const elasticAgentManagedManifest = \`---
EOF

cat $MANIFEST_PATH/$MANAGED >> $OUTPUT_FILE
echo -n "\`;" >> $OUTPUT_FILE

#Replacing all occurencies of elastic-agent-standalone
sed -i -e 's/elastic-agent-standalone/elastic-agent/g' $OUTPUT_FILE

#Remove ES_HOST entry from file
sed -i -e '/# The Elasticsearch host to communicate with/d' $OUTPUT_FILE
sed -i -e '/ES_HOST/d' $OUTPUT_FILE
sed -i -e '/value: ""/d' $OUTPUT_FILE