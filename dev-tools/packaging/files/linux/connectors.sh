#!/usr/bin/env bash

PY_AGENT_CLIENT_PATH=/usr/share/connectors
PYTHON_PATH=$PY_AGENT_CLIENT_PATH/.venv/bin/python
COMPONENT_PATH=$PY_AGENT_CLIENT_PATH/connectors/agent/cli.py
$PYTHON_PATH $COMPONENT_PATH
