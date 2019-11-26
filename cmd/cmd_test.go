/*
 * Copyright 2018-2019 The NATS Authors
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	cli "github.com/nats-io/cliprompts"
	"github.com/spf13/cobra"
)

type CmdTest struct {
	cmd        *cobra.Command
	args       []string
	hasOutput  []string
	hasError   []string
	shouldFail bool
}

func BuildChain(commands []string, cmd *cobra.Command) *cobra.Command {
	var root *cobra.Command
	var current *cobra.Command
	for _, n := range commands {
		c := &cobra.Command{
			Use:  n,
			Args: cobra.NoArgs,
		}
		if current != nil {
			current.AddCommand(c)
		}
		current = c
		if root == nil {
			root = current
		}

	}
	current.AddCommand(cmd)
	return root
}

type CmdTests []CmdTest

func (cts *CmdTests) Run(t *testing.T, chain ...string) {
	for i, v := range *cts {
		v.RunTest(t, chain, i)
	}
}

func (c *CmdTest) String() string {
	return strings.Join(c.args, " ")
}

func (c *CmdTest) RunTest(t *testing.T, chain []string, index int) {
	root := BuildChain(chain, c.cmd)
	stdout, stderr, err := ExecuteCmd(root, c.args...)
	for _, v := range c.hasOutput {
		if !strings.Contains(stdout, v) {
			t.Fatalf("test %d command '%v' stdout doesn't have %q\nstdout:\n%s\nstderr:\n%s\n", index, c, v, stdout, stderr)
		}
	}
	for _, v := range c.hasError {
		if !strings.Contains(stderr, v) {
			t.Fatalf("test %d command '%v' stderr doesn't have %q\nstdout:\n%s\nstderr:\n%s\n", index, c, v, stdout, stderr)
		}
	}
	if c.shouldFail && err == nil {
		t.Fatalf("test %d command '%v' should have failed but didn't\nstdout:\n%s\nstderr:\n%s\n", index, c, stdout, stderr)
	}
	if !c.shouldFail && err != nil {
		t.Fatalf("test %d command '%v' should have not failed: %v", index, c, err)
	}
}

func ExecuteCmd(root *cobra.Command, args ...string) (stdout string, stderr string, err error) {
	var stderrBuf, stdoutBuf bytes.Buffer
	root.SetOutput(&stderrBuf)
	if len(args) == 0 {
		args = make([]string, 0)
	}
	root.SetArgs(args)
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	_, err = root.ExecuteC()

	_ = w.Close()
	os.Stdout = old
	_, _ = io.Copy(&stdoutBuf, r)

	ResetSharedFlags()

	return stdoutBuf.String(), stderrBuf.String(), err
}

func ExecuteInteractiveCmd(root *cobra.Command, inputs []interface{}, args ...string) (stdout string, stderr string, err error) {
	var stderrBuf, stdoutBuf bytes.Buffer
	root.SetOutput(&stderrBuf)
	root.SetArgs(args)
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	InteractiveFlag = true
	cli.SetPromptLib(cli.NewTestPrompts(inputs))
	_, err = root.ExecuteC()
	cli.ResetPromptLib()
	InteractiveFlag = false

	_ = w.Close()
	os.Stdout = old
	_, _ = io.Copy(&stdoutBuf, r)

	ResetSharedFlags()

	return stdoutBuf.String(), stderrBuf.String(), err
}
