#!/usr/bin/env bash
set -euo pipefail

IMAGE="snorex"
CONTAINER="snorex"

docker build -t "$IMAGE" .

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true

docker run \
  --rm \
  --name "$CONTAINER" \
  -p 3500:3500 \
  "$IMAGE"