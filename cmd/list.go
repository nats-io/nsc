/*
 * Copyright 2018-2020 The NATS Authors
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
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nsc/v2/cmd/store"
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

type EntryInfo struct {
	Name   string
	Claims jwt.Claims
	Err    error
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
				fmt.Printf("no operators defined in store dir %q\n"+
					"init an environment or change the store root with `env --store <dir>`", config.StoreRoot)
			} else {
				sort.Strings(operators)
				var infos []*EntryInfo
				for _, v := range operators {
					var i EntryInfo
					infos = append(infos, &i)
					i.Name = v
					s, err := config.LoadStore(v)
					if err != nil {
						i.Err = err
						continue
					}
					c, err := s.LoadRootClaim()
					if err != nil {
						i.Err = err
						continue
					}
					if c == nil {
						i.Err = fmt.Errorf("%q jwt not found", v)
						continue
					}
					i.Claims = c
				}
				cmd.Println(listEntities("Operators", infos, config.Operator))
			}

			return nil
		},
	}
	return cmd
}

func ListAccounts(s *store.Store) ([]*EntryInfo, error) {
	accounts, err := s.ListSubContainers(store.Accounts)
	if err != nil {
		return nil, err
	}
	sort.Strings(accounts)

	var infos []*EntryInfo
	for _, v := range accounts {
		var i EntryInfo
		i.Name = v
		infos = append(infos, &i)
		ac, err := s.ReadAccountClaim(v)
		if err != nil {
			i.Err = err
			continue
		}
		i.Claims = ac
	}
	return infos, nil
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

			var infos []*EntryInfo
			for _, v := range containers {
				var i EntryInfo
				i.Name = v
				infos = append(infos, &i)
				ac, err := s.ReadAccountClaim(v)
				if err != nil {
					i.Err = err
					continue
				}
				i.Claims = ac
			}
			cmd.Println(listEntities("Accounts", infos, config.Account))
			return nil
		},
	}

	cmd.Flags().StringVarP(&operator, "operator", "o", "", "operator name")

	return cmd
}

func ListUsers(s *store.Store, accountName string) ([]*EntryInfo, error) {
	names, err := s.ListEntries(store.Accounts, accountName, store.Users)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)

	var infos []*EntryInfo
	for _, v := range names {
		var i EntryInfo
		i.Name = v
		infos = append(infos, &i)
		uc, err := s.ReadUserClaim(accountName, v)
		if err != nil {
			i.Err = err
			continue
		}
		if uc == nil {
			i.Err = fmt.Errorf("%q jwt not found", v)
			continue
		}
		i.Claims = uc
	}
	return infos, nil
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

			infos, err := ListUsers(s, config.Account)
			if err != nil {
				return err
			}

			cmd.Println(listEntities("Users", infos, config.Account))
			return nil
		},
	}

	cmd.Flags().StringVarP(&operator, "operator", "o", "", "operator name")
	cmd.Flags().StringVarP(&account, "account", "a", "", "account name")

	return cmd
}

func listEntities(title string, infos []*EntryInfo, current string) string {
	table := tablewriter.CreateTable()
	table.AddTitle(title)
	if len(infos) == 0 {
		table.AddRow("No entries defined")
	} else {
		table.AddHeaders("Name", "Public Key")
		for _, v := range infos {
			n := v.Name
			var p string
			if v.Err != nil || v.Claims == nil {
				p = fmt.Sprintf("error loading jwt - %v", v.Err)
			} else {
				c := v.Claims.Claims()
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
