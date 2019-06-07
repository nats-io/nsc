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

	// disable update check if running a locally built version
	if version != "0.0.0-dev" {
		u, err := cmd.NewSelfUpdate()
		if err != nil {
			// not fatal
			cmd.GetRootCmd().Printf("error checking for updates: %v\n", err)
		}
		if u != nil {
			m, err := u.Run()
			if err != nil {
				cmd.GetRootCmd().Printf("error checking for updates: %v\n", err)
			}
			if m != nil {
				cmd.GetRootCmd().Printf("new version available %s - `nsc update` to update.\n", m.String())
			}
		}
	}

	cmd.Execute()
}
