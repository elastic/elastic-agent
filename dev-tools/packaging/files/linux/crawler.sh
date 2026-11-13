#!/usr/bin/env bash

# Launches the Elastic Open Web Crawler as an agent component. The JRE is installed from the
# base image's packages; the crawler and its JRuby runtime are copied from the crawler image
# (see Dockerfile.elastic-agent.tmpl).
CRAWLER_HOME=/usr/share/crawler
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
export PATH=$JAVA_HOME/bin:/opt/jruby/bin:/usr/local/bundle/bin:$PATH
export GEM_HOME=/usr/local/bundle
export BUNDLE_APP_CONFIG=/usr/local/bundle
export BUNDLE_SILENCE_ROOT_WARNING=1
export IS_DOCKER=1

cd "$CRAWLER_HOME"
exec /opt/jruby/bin/jruby bin/crawler "$@"
