// Copyright 2018-2022 The NATS Authors
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
	"github.com/spf13/cobra"
)

func init() {
	GetRootCmd().AddCommand(createSelecteCmd())
}

func createSelecteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "select",
		Short: "Set the current operator or account",
	}
	cmd.AddCommand(selectOperatorCmd())
	cmd.AddCommand(selectAccountCmd())
	return cmd
}

func selectOperatorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "operator",
		Short: "set the operator",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			current := GetConfig()
			if err := current.ContextConfig.Update("", args[0], ""); err != nil {
				return err
			}

			return current.Save()
		},
	}
}

func selectAccountCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "account",
		Short: "set the account",
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			current := GetConfig()
			if err := current.ContextConfig.Update("", "", args[0]); err != nil {
				return err
			}

			return current.Save()
		},
	}
}
