// Copyright 2018-2025 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func numberEditorCmd(params *NumberParams) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "env",
		Short:         fmt.Sprintf("Prints and manage the %s environment", GetToolName()),
		SilenceErrors: false,
		SilenceUsage:  false,
		Example:       "env",
		RunE: func(cmd *cobra.Command, args []string) error {
			if InteractiveFlag {
				if err := params.Edit("enter a number"); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().VarP(params, "number", "n", "some number")

	return cmd
}

func TestNumberParams_BindFlags(t *testing.T) {
	var p NumberParams
	cmd := numberEditorCmd(&p)
	_, err := ExecuteCmd(cmd, []string{"--number", "10"}...)
	require.NoError(t, err)

	require.Equal(t, NumberParams(10), p)
}

func TestNumberParams_Edit(t *testing.T) {
	var p NumberParams
	cmd := numberEditorCmd(&p)
	_, err := ExecuteInteractiveCmd(cmd, []interface{}{"404"})
	require.NoError(t, err)

	require.Equal(t, NumberParams(404), p)
}
