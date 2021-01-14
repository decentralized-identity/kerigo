#!/bin/bash

set -e
echo -n > coverage.out
echo "Running $0"

GO_TEST_CMD="go test"

PKGS=$(go list github.com/decentralized-identity/kerigo/... 2> /dev/null | grep -v vendor)
$GO_TEST_CMD $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
if [ -f profile.out ]; then
  cat profile.out >>coverage.out
  rm profile.out
fi
