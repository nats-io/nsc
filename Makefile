CWD:=$(shell echo `pwd`)
BUILD_DIR:=$(CWD)/build
BUILD_OS:=`go env GOOS`
BUILD_OS_ARCH:=`go env GOARCH`
BUILD_OS_GOPATH=`go env GOPATH`

.PHONY: build

build: fmt compile test

fmt:
	gofmt -s -w *.go
	gofmt -s -w cli/*.go
	gofmt -s -w cmd/*.go
	gofmt -s -w cmd/store/*.go
	gofmt -s -w cmd/kstore/*.go

	goimports -w *.go
	goimports -w cli/*.go
	goimports -w cmd/*.go
	goimports -w cmd/store/*.go
	goimports -w cmd/kstore/*.go

compile:
	goreleaser --snapshot --rm-dist --skip-validate --skip-publish --parallelism 8

install: build
	cp $(BUILD_DIR)/$(BUILD_OS)_$(BUILD_OS_ARCH)/* $(BUILD_OS_GOPATH)/bin

cover: test
	gocovmerge ./cov/*.out > build/coverage.out
	go tool cover -html=build/coverage.out

test: fmt
	go vet ./...
	rm -rf ./cov
	mkdir cov
	go test -covermode=atomic -coverprofile=./cov/cli.out ./cli
	go test -covermode=atomic -coverprofile=./cov/cmd.out ./cmd
	go test -covermode=atomic -coverprofile=./cov/cmdstore.out ./cmd/store
	go test -covermode=atomic -coverprofile=./cov/kstore.out ./cmd/kstore

