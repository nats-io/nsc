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
	var params SetContextParams
	cmd := &cobra.Command{
		Use:           "env",
		Short:         fmt.Sprintf("Prints and manage the %s environment", filepath.Base(os.Args[0])),
		Args:          cobra.MaximumNArgs(0),
		SilenceErrors: false,
		SilenceUsage:  false,
		Example:       "env",
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = params.Run()
			params.PrintEnv(cmd)
			return nil
		},
	}

	cmd.Flags().StringVarP(&params.StoreRoot, "store", "s", "", "set store directory")
	cmd.Flags().StringVarP(&params.Operator, "operator", "o", "", "set operator name")
	cmd.Flags().StringVarP(&params.Account, "account", "a", "", "set account name")
	cmd.Flags().StringVarP(&params.Cluster, "cluster", "c", "", "set cluster name")

	return cmd
}

func init() {
	GetRootCmd().AddCommand(createEnvCmd())
}

type SetContextParams struct {
	StoreRoot string
	Operator  string
	Account   string
	Cluster   string
}

func (p *SetContextParams) Run() error {
	if *p == (SetContextParams{}) {
		// no edits
		return nil
	}
	current := GetConfig()

	root := current.StoreRoot
	if p.StoreRoot != "" {
		root = p.StoreRoot
	}

	c, err := NewContextConfig(root)
	if err != nil {
		return err
	}

	if p.Operator != "" {
		if err := c.SetOperator(p.Operator); err != nil {
			return err
		}
	}
	if p.Account != "" {
		if err := c.SetAccount(p.Account); err != nil {
			return err
		}
	}
	if p.Cluster != "" {
		if err := c.SetCluster(p.Cluster); err != nil {
			return err
		}
	}
	c.SetDefaults()

	current.ContextConfig = *c

	return current.Save()
}

func (p *SetContextParams) PrintEnv(cmd *cobra.Command) {
	conf := GetConfig()
	table := tablewriter.CreateTable()
	table.UTF8Box()
	table.AddTitle("NSC Environment")
	table.AddHeaders("Setting", "Set", "Effective Value")
	table.AddRow("$"+store.NKeysPathEnv, envSet(store.NKeysPathEnv), store.GetKeysDir())
	table.AddRow("$"+homeEnv, envSet(homeEnv), toolHome)
	table.AddSeparator()
	r := conf.StoreRoot
	if r == "" {
		r = "Not Set"
	}
	table.AddRow("Stores Dir", "", r)
	table.AddRow("Default Operator", "", conf.Operator)
	table.AddRow("Default Account", "", conf.Account)
	table.AddRow("Default Cluster", "", conf.Cluster)
	cmd.Println(table.Render())
}
