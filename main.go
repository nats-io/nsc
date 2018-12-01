package main

import (
	"log"
	"strings"

	"github.com/nats-io/nsc/cmd"
)

// the cli injects the version
var version = "0.0.0-dev"

func main() {
	// sem version gets very angry if there's a v in the release
	if strings.HasPrefix(version, "v") || strings.HasPrefix(version, "V") {
		version = version[1:]
	}
	cmd.GetRootCmd().Version = version
	//cmd.SetUpdateRespository("nats-io/nsc")

	if err := cmd.LoadOrInit("nats-io/nsc", cmd.NgsHomeEnv); err != nil {
		log.Fatal(err)
	}

	//u, err := cmd.NewSelfUpdate()
	//if err != nil {
	//	// not fatal
	//	cmd.GetRootCmd().Printf("error checking for updates: %v\n", err)
	//}
	//if u != nil {
	//	m, err := u.Run()
	//	if err != nil {
	//		cmd.GetRootCmd().Printf("error checking for updates: %v\n", err)
	//	}
	//	if m != nil {
	//		cmd.GetRootCmd().Printf("new version available %s - `nsc update` to update.\n", m.String())
	//	}
	//}

	cmd.Execute()
}
