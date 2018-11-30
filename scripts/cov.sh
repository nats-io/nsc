#!/bin/bash -e
# this script is intended for travis - `make cover`
# Run from directory above via ./scripts/cov.sh

rm -rf ./coverage.out
go test -coverpkg=./... -coverprofile=./coverage.out ./...

# If we have an arg, assume travis run and push to coveralls. Otherwise launch browser results
if [[ -n $1 ]]; then
    $HOME/gopath/bin/goveralls -coverprofile=coverage.out -service travis-ci
    rm -rf ./coverage.out
else
    go tool cover -html=coverage.out
fi
