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

	goimports -w *.go
	goimports -w cli/*.go
	goimports -w cmd/*.go
	goimports -w cmd/store/*.go

compile:
	goreleaser --snapshot --rm-dist --skip-validate --skip-publish --parallelism 8

install: build
	cp $(BUILD_DIR)/$(BUILD_OS)_$(BUILD_OS_ARCH)/* $(BUILD_OS_GOPATH)/bin

install-no-test:
	cp $(BUILD_DIR)/$(BUILD_OS)_$(BUILD_OS_ARCH)/* $(BUILD_OS_GOPATH)/bin

cover: test
	go tool cover -html=./coverage.out

test: fmt
	go vet ./...
	rm -rf ./coverage.out
	go test -coverpkg=./... -coverprofile=./coverage.out ./...

