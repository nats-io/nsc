package main

import (
	"github.com/nats-io/nsc/cmd"
)

// the cli injects the version
var version = "0.0.0.dev"

func main() {
	cmd.GetRootCmd().Version = version
	cmd.SetUpdateRespository("nats-io/nsc")

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
		if m != "" {
			cmd.GetRootCmd().Printf("new version available %s - `nsc update` to update.\n", m)
		}
	}

	cmd.Execute()
}
