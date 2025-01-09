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
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func listEditorCmd(params *ListEditorParam) *cobra.Command {
	cmd := &cobra.Command{
		Use: "test",
		RunE: func(cmd *cobra.Command, args []string) error {
			if InteractiveFlag {
				return params.Edit()
			}
			return params.Valid()
		},
	}
	cmd.Flags().StringSliceVarP(&params.Values, params.FlagName, "", nil, "")
	return cmd
}

func TestListEditorParams(t *testing.T) {
	var p ListEditorParam
	p.FlagName = "test"
	validatorCalled := false
	p.ValidatorFn = func(string) error {
		validatorCalled = true
		return nil
	}
	cmd := listEditorCmd(&p)
	_, err := ExecuteCmd(cmd, []string{"--test", "a", "--test", "b"}...)
	require.NoError(t, err)
	require.True(t, validatorCalled)
	require.Len(t, p.Values, 2)
	require.EqualValues(t, p.Values, []string{"a", "b"})
}

func TestListEditorParams_Interactive(t *testing.T) {
	var p ListEditorParam
	p.FlagName = "test"
	validatorCalled := false
	p.ValidatorFn = func(string) error {
		validatorCalled = true
		return nil
	}
	cmd := listEditorCmd(&p)
	_, err := ExecuteInteractiveCmd(cmd, []interface{}{true, "x", true, "y", false})
	require.NoError(t, err)
	require.True(t, validatorCalled)
	require.Len(t, p.Values, 2)
	require.EqualValues(t, p.Values, []string{"x", "y"})
}

func TestListEditorParams_InteractiveEdit(t *testing.T) {
	p := &ListEditorParam{}
	p.FlagName = "test"
	validatorCalled := false
	p.ValidatorFn = func(string) error {
		validatorCalled = true
		return nil
	}
	cmd := listEditorCmd(p)
	_, err := ExecuteInteractiveCmd(cmd, []interface{}{"aa", "bb", true, "x", true, "y", false}, "--test", "a", "--test", "b")
	require.NoError(t, err)
	require.True(t, validatorCalled)
	require.Len(t, p.Values, 4)
	require.EqualValues(t, p.Values, []string{"aa", "bb", "x", "y"})
	require.EqualValues(t, p.GetValues(), []string{"aa", "bb", "x", "y"})

	t.Log()
}
