/*
 * Copyright 2018 The NATS Authors
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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func genericParamsCmd(params *GenericParams) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "env",
		Short:         fmt.Sprintf("Prints and manage the %s environment", filepath.Base(os.Args[0])),
		SilenceErrors: false,
		SilenceUsage:  false,
		Example:       "env",
		RunE: func(cmd *cobra.Command, args []string) error {
			params.Validate()

			if InteractiveFlag {
				if err := params.Edit(); err != nil {
					return err
				}
			}
			return nil
		},
	}
	params.BindFlags(cmd)
	return cmd
}

func TestGenericParams_BindFlags(t *testing.T) {
	var p GenericParams
	cmd := genericParamsCmd(&p)
	_, _, err := ExecuteCmd(cmd, "--tags", "a")
	require.NoError(t, err)

	require.Contains(t, p.tags, "a")
}

func TestGenericParams_Edit(t *testing.T) {
	var p GenericParams
	cmd := genericParamsCmd(&p)
	_, _, err := ExecuteInteractiveCmd(cmd, []interface{}{"a,b,c"})
	require.NoError(t, err)

	require.ElementsMatch(t, p.tags, []string{"a", "b", "c"})
}
