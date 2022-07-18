#!/bin/bash

VERSION=8.3.2
FLEET_URL=https://change.me:443
FLEET_ENROLLMENT_TOKEN=CHANGE_ME

cd /opt
curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${VERSION}-linux-arm64.tar.gz
tar xzvf elastic-agent-${VERSION}-linux-arm64.tar.gz
cd elastic-agent-${VERSION}-linux-arm64
./elastic-agent install --url="${FLEET_URL}" --enrollment-token="${FLEET_ENROLLMENT_TOKEN}"

# EOF
