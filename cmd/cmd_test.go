/*
 * Copyright 2018-2025 The NATS Authors
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
	"strings"
	"testing"

	cli "github.com/nats-io/cliprompts/v2"
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
	out, err := ExecuteCmd(root, c.args...)
	for _, v := range c.hasOutput {
		if !strings.Contains(out.Out, v) {
			t.Fatalf("test %d command '%v' stdout doesn't have %q\nstdout:\n%s\nstderr:\n%s\n", index, c, v, out.Out, out.Err)
		}
	}
	for _, v := range c.hasError {
		if !strings.Contains(out.Err, v) {
			t.Fatalf("test %d command '%v' stderr doesn't have %q\nstdout:\n%s\nstderr:\n%s\n", index, c, v, out.Out, out.Err)
		}
	}
	if c.shouldFail && err == nil {
		t.Fatalf("test %d command '%v' should have failed but didn't\nstdout:\n%s\nstderr:\n%s\n", index, c, out.Out, out.Err)
	}
	if !c.shouldFail && err != nil {
		t.Fatalf("test %d command '%v' should have not failed: %v", index, c, err)
	}
}

type CmdOutput struct {
	Out string
	Err string
}

func ExecuteCmd(root *cobra.Command, args ...string) (CmdOutput, error) {
	var stderrBuf, stdoutBuf bytes.Buffer
	root.SetOut(&stdoutBuf)
	root.SetErr(&stderrBuf)

	if len(args) == 0 {
		args = make([]string, 0)
	}
	root.SetArgs(args)
	_, err := root.ExecuteC()

	ResetSharedFlags()
	return CmdOutput{Out: stdoutBuf.String(), Err: stderrBuf.String()}, err
}

func ExecuteInteractiveCmd(root *cobra.Command, inputs []interface{}, args ...string) (out CmdOutput, err error) {
	InteractiveFlag = true
	cli.SetPromptLib(cli.NewTestPrompts(inputs))
	out, err = ExecuteCmd(root, args...)
	cli.ResetPromptLib()
	InteractiveFlag = false
	return out, err
}
