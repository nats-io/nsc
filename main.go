package main

import (
	"log"

	"github.com/nats-io/nsc/cmd"
)

// the cli injects the version
var version = "0.0.0-dev"

func main() {
	cmd.SetToolName("nsc")
	conf, err := cmd.LoadOrInit("nats-io/nsc", cmd.NscHomeEnv)
	if err != nil {
		log.Fatal(err)
	}
	conf.SetVersion(version)
	cmd.Execute()
}
