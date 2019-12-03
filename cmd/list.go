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

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
	"github.com/xlab/tablewriter"
)

// addCmd represents the add command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List assets such as accounts, imports, users",
}

func init() {
	GetRootCmd().AddCommand(listCmd)
	listCmd.AddCommand(createListOperatorsCmd())
	listCmd.AddCommand(createListAccountsCmd())
	listCmd.AddCommand(createListUsersCmd())
}

type listEntry struct {
	name   string
	claims jwt.Claims
	err    error
}

func createListOperatorsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "operators",
		Short: "List operators",
		Args:  MaxArgs(0),
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
				var infos []*listEntry
				for _, v := range operators {
					var i listEntry
					infos = append(infos, &i)
					i.name = v
					s, err := config.LoadStore(v)
					if err != nil {
						i.err = err
						continue
					}
					c, err := s.LoadRootClaim()
					if err != nil {
						i.err = err
						continue
					}
					if c == nil {
						i.err = fmt.Errorf("%q jwt not found", v)
						continue
					}
					i.claims = c
				}
				cmd.Println(listEntities("Operators", infos, config.Operator))
			}

			return nil
		},
	}
	return cmd
}

func createListAccountsCmd() *cobra.Command {
	var operator string

	cmd := &cobra.Command{
		Use:   "accounts",
		Short: "List accounts",
		Args:  MaxArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			config := GetConfig()
			if config.StoreRoot == "" {
				return errors.New("no store set - `env --store <dir>`")
			}
			if operator != "" {
				if err := config.SetOperator(operator); err != nil {
					return err
				}
			}
			if config.Operator == "" {
				return errors.New("no operator set - `env --operator <name>`")
			}
			containers, err := config.ListAccounts()
			if err != nil {
				return err
			}
			sort.Strings(containers)
			s, err := config.LoadStore(config.Operator)
			if err != nil {
				return err
			}

			var infos []*listEntry
			for _, v := range containers {
				var i listEntry
				i.name = v
				infos = append(infos, &i)
				ac, err := s.ReadAccountClaim(v)
				if err != nil {
					i.err = err
					continue
				}
				i.claims = ac
			}
			cmd.Println(listEntities("Accounts", infos, config.Account))
			return nil
		},
	}

	cmd.Flags().StringVarP(&operator, "operator", "o", "", "operator name")

	return cmd
}

func createListUsersCmd() *cobra.Command {
	var operator string
	var account string
	cmd := &cobra.Command{
		Use:   "users",
		Short: "List users",
		Args:  MaxArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			config := GetConfig()
			if config.StoreRoot == "" {
				return fmt.Errorf("no store set - `%s env --store <dir>`", GetToolName())
			}
			if operator != "" {
				if err := config.SetOperator(operator); err != nil {
					return err
				}
			}
			if config.Operator == "" {
				return fmt.Errorf("no operator set - `%s env --operator <name>`", GetToolName())
			}
			if account != "" {
				if err := config.SetAccount(account); err != nil {
					return err
				}
			}
			if config.Account == "" {
				return fmt.Errorf("no account set - `%s env --account <name>`", GetToolName())
			}

			s, err := config.LoadStore(config.Operator)
			if err != nil {
				return err
			}

			names, err := s.ListEntries(store.Accounts, config.Account, store.Users)
			if err != nil {
				return err
			}
			sort.Strings(names)

			var infos []*listEntry
			for _, v := range names {
				var i listEntry
				i.name = v
				infos = append(infos, &i)
				uc, err := s.ReadUserClaim(config.Account, v)
				if err != nil {
					i.err = err
					continue
				}
				if uc == nil {
					i.err = fmt.Errorf("%q jwt not found", v)
					continue
				}
				i.claims = uc
			}
			cmd.Println(listEntities("Users", infos, config.Account))
			return nil
		},
	}

	cmd.Flags().StringVarP(&operator, "operator", "o", "", "operator name")
	cmd.Flags().StringVarP(&account, "account", "a", "", "account name")

	return cmd
}

func listEntities(title string, infos []*listEntry, current string) string {
	table := tablewriter.CreateTable()
	table.UTF8Box()
	table.AddTitle(title)
	if len(infos) == 0 {
		table.AddRow("No entries defined")
	} else {
		table.AddHeaders("Name", "Public Key")
		for _, v := range infos {
			n := v.name
			var p string
			if v.err != nil || v.claims == nil {
				p = fmt.Sprintf("error loading jwt - %v", v.err)
			} else {
				c := v.claims.Claims()
				if c != nil {
					tn := c.Name
					if n != tn {
						n = fmt.Sprintf("%s (%s)", n, c.Name)
					}
					p = c.Subject
				}
			}
			if n == current {
				n = cli.Bold(n)
				p = cli.Bold(p)
			}
			table.AddRow(n, p)
		}
	}
	return table.Render()
}
