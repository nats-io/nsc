#!/bin/bash -e
# this script is intended for travis - `make cover`
# Run from directory above via ./scripts/cov.sh

rm -rf ./cov
mkdir cov
go test -covermode=atomic -coverprofile=./cov/cli.out ./cli
go test -covermode=atomic -coverprofile=./cov/cmd.out ./cmd
go test -covermode=atomic -coverprofile=./cov/cmdstore.out ./cmd/store
gocovmerge ./cov/*.out > build/coverage.out
rm -rf ./cov

# If we have an arg, assume travis run and push to coveralls. Otherwise launch browser results
if [[ -n $1 ]]; then
    $HOME/gopath/bin/goveralls -coverprofile=coverage.out -service travis-ci
    rm -rf ./coverage.out
else
    go tool cover -html=coverage.out
fi
