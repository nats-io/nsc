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
	"github.com/spf13/cobra"
)

func createSetContextCmd() *cobra.Command {
	var params SetContextParams
	cmd := &cobra.Command{
		Use:          "set",
		Short:        "Set the context for the stores, operator, account or cluster",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {

			current := *GetConfig()

			root := current.StoreRoot
			if params.StoreRoot != "" {
				root = params.StoreRoot
			}

			c, err := NewContextConfig(root)
			if err != nil {
				return err
			}
			if params.Operator != "" {
				if err := c.SetOperator(params.Operator); err != nil {
					return err
				}
			}
			if params.Account != "" {
				if err := c.SetAccount(params.Account); err != nil {
					return err
				}
			}
			if params.Cluster != "" {
				if err := c.SetCluster(params.Cluster); err != nil {
					return err
				}
			}

			current.ContextConfig = *c
			return current.Save()
		},
	}

	cmd.Flags().StringVarP(&params.StoreRoot, "store", "s", "", "store directory")
	cmd.Flags().StringVarP(&params.StoreRoot, "operator", "o", "", "operator name")
	cmd.Flags().StringVarP(&params.StoreRoot, "account", "a", "", "account name")
	cmd.Flags().StringVarP(&params.StoreRoot, "cluster", "c", "", "cluster name")

	return cmd
}

func init() {
	rootCmd.AddCommand(createSetContextCmd())
}

type SetContextParams struct {
	StoreRoot string
	Operator  string
	Account   string
	Cluster   string
}
