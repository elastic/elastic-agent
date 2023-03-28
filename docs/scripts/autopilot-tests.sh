#!/bin/bash
# Script that asserts the integration of Elastic Agent+Kubernetes Integration with Elastic Stack. 
## Tested with Agent version > 8.6.0

NAMESPACE=${1:-"kube-system"}
LEADER=$(kubectl get leases -n ${NAMESPACE} | grep elastic | awk '{print $2}' | awk -F- '{print $NF}')
LEADERAGENT=${2-"elastic-agent-${LEADER}"}

# Check if all agents are running
RUNNINGAGENTS=$(kubectl get pods -n ${NAMESPACE} | grep elastic-agent | grep -iv Running | wc -l)
if [ $RUNNINGAGENTS -ge 1 ]; then
    echo "Not all agents are running. Failing..."
    STATUS=1
    exit $STATUS;
fi

#Test 1: Validate if connection between Agent and Elasticsearch has been established”
function test1 (){
  Result1=$(kubectl logs -n ${NAMESPACE} ${LEADERAGENT} | grep -i "Connection to backof" | grep '"service.name":"metricbeat"' | tail -2 | grep -v error | wc -l)
  if [ $Result1 -eq 2 ]; then
    #echo "Connection to backoff Establsihed"
    echo "Test1 - PASS"
    STATUS=0
  else
    #echo "Connection to backoff not Establsihed!"
    echo "Test1 - FAIL"
    STATUS=2
  fi    
}

test1

#Test 2: Validate if metrics are sent to Elasticsearch
function test2 (){
  Result2=$(kubectl logs -n ${NAMESPACE} ${LEADERAGENT} --since 1m | grep -i "Non-zero metrics in the last" | grep -i metricbeat | grep "kubernetes/metrics" | wc -l)
  if [ $Result2 -ne 0 ]; then
    #echo "Agent Started receiving Metrics"
    echo "Test2 - PASS"
    STATUS=0
  else
    #echo "Agent does not send Metrics!"
    echo "Test2 - FAIL"
    STATUS=2
  fi    
}

test2

#Test 3: Repeat tests for period of time

secs=300   # Set interval (duration) in seconds. 5min = 300 sec
sleepsec=60
SECONDS=0   # Reset $SECONDS; counting of seconds will (re)start from 0(-ish).
echo "Starting execution of tests for 5 min"
while (( SECONDS < secs )); do    # Loop until interval has elapsed.
  sleep $sleepsec
  test1
  test2
done


#Test 4: Validate errors 

ERRORSFOUND=$(kubectl logs -n ${NAMESPACE} ${LEADERAGENT} --since 5m | grep -i "error" | grep -v "UUID cannot be determined" | grep -i metricbeat | wc -l)
if [ $ERRORSFOUND -eq 0 ]; then
    #echo "No Erros Found!"
    echo "Test4 - PASS"
    STATUS=0
  else
    #echo "Erros Found! Please advise logs"
    echo "Test4 - Conditional PASS"
    STATUS=1
  fi    


if [ $STATUS -eq 0 ]; then
    echo "Overall Test - PASS"
elif [ $STATUS -eq 1 ]; then
    echo "Overall Test - Conditional PASS"
else 
    echo "Overall Test - FAIL"
fi    

