// +build !windows,!darwin

package cli

import "os/exec"

func open(url string) *exec.Cmd {
	return nil
}
