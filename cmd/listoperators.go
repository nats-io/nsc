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
	"errors"
	"fmt"
	"sort"

	"github.com/nats-io/nsc/cli"
	"github.com/spf13/cobra"
	"github.com/xlab/tablewriter"
)

func createListOperatorsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "operators",
		Short: "List operators",
		RunE: func(cmd *cobra.Command, args []string) error {
			config := GetConfig()
			if config.StoreRoot == "" {
				return errors.New("no store set - `env --store <dir>`")
			}
			operators := config.ListOperators()
			if len(operators) == 0 {
				fmt.Println("no operators defined - init an environment")
			} else {
				sort.Strings(operators)
				table := tablewriter.CreateTable()
				table.UTF8Box()
				table.AddTitle("Operators")
				table.AddHeaders("Name", "Managed", "Public Key")
				for _, v := range operators {
					pub := ""
					managed := "No"
					s, err := config.LoadStore(v)
					if err == nil && s != nil {
						pub, _ = s.GetRootPublicKey()
						if s.IsManaged() {
							managed = "Yes"
						}
					}
					if v == config.Operator {
						v = cli.Italic(v)
						pub = cli.Italic(pub)
						managed = cli.Italic(managed)
					}
					table.AddRow(v, managed, pub)
				}
				fmt.Println(table.Render())
			}

			return nil
		},
	}
	return cmd
}

func createListAccountsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "accounts",
		Short: "List accounts",
		RunE: func(cmd *cobra.Command, args []string) error {
			config := GetConfig()
			if config.StoreRoot == "" {
				return errors.New("no store set - `env --store <dir>`")
			}
			if config.Operator == "" {
				return errors.New("no operator set - `env --operator <name>`")
			}

			containers, err := config.ListAccounts()
			if err != nil {
				return err
			}
			if len(containers) == 0 {
				fmt.Println("no accounts defined - add an account")
			} else {
				s, err := config.LoadStore(config.Operator)
				if err != nil {
					return err
				}

				sort.Strings(containers)
				table := tablewriter.CreateTable()
				table.UTF8Box()
				table.AddTitle("Accounts")
				table.AddHeaders("Name", "Public Key")

				ctx, err := s.GetContext()
				if err != nil {
					return err
				}
				for _, v := range containers {
					pub, _ := ctx.KeyStore.GetAccountPublicKey(v)
					if v == config.Account {
						v = cli.Italic(v)
						pub = cli.Italic(pub)
					}
					table.AddRow(v, pub)
				}
				fmt.Println(table.Render())
			}

			return nil
		},
	}
	return cmd
}

func createListClustersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clusters",
		Short: "List clusters",
		RunE: func(cmd *cobra.Command, args []string) error {
			config := GetConfig()
			if config.StoreRoot == "" {
				return errors.New("no store set - `env --store <dir>`")
			}
			if config.Operator == "" {
				return errors.New("no operator set - `env --operator <name>`")
			}

			containers, err := config.ListClusters()
			if err != nil {
				return err
			}
			if len(containers) == 0 {
				fmt.Println("no clusters defined - add a cluster")
			} else {
				s, err := config.LoadStore(config.Operator)
				if err != nil {
					return err
				}

				sort.Strings(containers)
				table := tablewriter.CreateTable()
				table.UTF8Box()
				table.AddTitle("Clusters")
				table.AddHeaders("Name", "Public Key")

				ctx, err := s.GetContext()
				if err != nil {
					return err
				}
				for _, v := range containers {
					pub, _ := ctx.KeyStore.GetClusterPublicKey(v)
					if v == config.Cluster {
						v = cli.Italic(v)
						pub = cli.Italic(pub)
					}
					table.AddRow(v, pub)
				}
				fmt.Println(table.Render())
			}

			return nil
		},
	}
	return cmd
}

func init() {
	listCmd.AddCommand(createListOperatorsCmd())
	listCmd.AddCommand(createListAccountsCmd())
	listCmd.AddCommand(createListClustersCmd())
}
