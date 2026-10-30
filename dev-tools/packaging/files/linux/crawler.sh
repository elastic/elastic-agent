#!/usr/bin/env bash

# Launches the Elastic Open Web Crawler as an agent component. The crawler, its JRuby runtime
# and its JDK are copied from the crawler image into the service image (see Dockerfile.elastic-agent.tmpl).
CRAWLER_HOME=/usr/share/crawler
export JAVA_HOME=/opt/jdk-crawler
export PATH=/opt/jdk-crawler/bin:/opt/jruby/bin:/usr/local/bundle/bin:$PATH
export GEM_HOME=/usr/local/bundle
export BUNDLE_APP_CONFIG=/usr/local/bundle
export BUNDLE_SILENCE_ROOT_WARNING=1
export IS_DOCKER=1

cd "$CRAWLER_HOME"
exec /opt/jruby/bin/jruby bin/crawler "$@"
