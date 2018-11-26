package main

import (
	"github.com/nats-io/nsc/cmd"
)

// the cli injects the version
var version = "0.0.0.dev"

func main() {
	cmd.GetRootCmd().Version = version
	cmd.Execute()
}
