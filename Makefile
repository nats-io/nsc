CWD:=$(shell echo `pwd`)
BUILD_DIR:=$(CWD)/build
BUILD_OS:=`go env GOOS`
BUILD_OS_ARCH:=`go env GOARCH`
BUILD_OS_GOPATH=`go env GOPATH`

.PHONY: build test release

build: compile

fmt:
	gofmt -s -w *.go
	gofmt -s -w cli/*.go
	gofmt -s -w cmd/*.go
	gofmt -s -w cmd/store/*.go

	goimports -w *.go
	goimports -w cli/*.go
	goimports -w cmd/*.go
	goimports -w cmd/store/*.go

	go mod tidy

compile:
	goreleaser --snapshot --rm-dist --skip-validate --skip-publish --parallelism 12

install: compile build
	cp $(BUILD_DIR)/nsc_$(BUILD_OS)_$(BUILD_OS_ARCH)/* $(BUILD_OS_GOPATH)/bin

cover: test
	go tool cover -html=./coverage.out

test:
	go mod vendor
	go vet ./...
	rm -rf ./coverage.out
	go test -coverpkg=./... -coverprofile=./coverage.out ./...

release: fmt test compile
