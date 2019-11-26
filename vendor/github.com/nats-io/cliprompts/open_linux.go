// +build !windows,!darwin

package cliprompts

import "os/exec"

func open(url string) *exec.Cmd {
	return nil
}
