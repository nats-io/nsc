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
	"os"

	"github.com/nats-io/nsc/cmd/store"

	"github.com/spf13/cobra"
	"github.com/xlab/tablewriter"
)

func envSet(varName string) string {
	if os.Getenv(varName) == "" {
		return "No"
	}
	return "Yes"
}

func createEnvCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "env",
		Short:         "Prints the nsc environment",
		SilenceErrors: true,
		SilenceUsage:  true,
		Example:       "env",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := getStore()

			table := tablewriter.CreateTable()
			table.UTF8Box()
			table.AddTitle("NSC Environment")
			table.AddHeaders("Setting", "Set", "Effective Value")

			table.AddRow("$"+store.NKeysPathEnv, envSet(store.NKeysPathEnv), store.GetKeysDir())
			if s == nil {
				table.AddRow("Configuration Dir", "No", "not in a configuration directory")
			} else {
				table.AddRow("Configuration Dir", "Yes", s.Dir)

				var ctx *store.Context
				if s != nil {
					ctx, err = s.GetContext()
				}
				if err != nil {
					table.AddRow("Store Context", "", err.Error())
				} else {
					fn := func(s string) string {
						if s == "" {
							return "No"
						}
						return "Yes"
					}
					table.AddRow("Operator", fn(ctx.Operator.Name), ctx.Operator.Name)
					table.AddRow("Account", fn(ctx.Account.Name), ctx.Account.Name)
					table.AddRow("Cluster", fn(ctx.Cluster.Name), ctx.Cluster.Name)
				}
			}

			cmd.Println(table.Render())

			return nil
		},
	}

	return cmd
}

func init() {
	rootCmd.AddCommand(createEnvCmd())
}
