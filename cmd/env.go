/*
 * Copyright 2018-2022 The NATS Authors
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
	"path"

	"github.com/mitchellh/go-homedir"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
	"github.com/xlab/tablewriter"
)

func envSet(varName string) string {
	_, ok := os.LookupEnv(varName)
	return yn(ok)
}

func yn(v bool) string {
	if v {
		return "Yes"
	}
	return "No"

}

func createEnvCmd() *cobra.Command {
	var params SetContextParams
	cmd := &cobra.Command{
		Use:           "env",
		Short:         fmt.Sprintf("Prints and manage the %s environment", GetToolName()),
		Args:          MaxArgs(0),
		SilenceErrors: false,
		SilenceUsage:  false,
		Example:       "env",
		RunE: func(cmd *cobra.Command, args []string) error {
			if NscCwdOnly && (params.StoreRoot != "" || params.Operator != "" || params.Account != "") {
				return fmt.Errorf("$%s is set - change your cwd to change context", NscCwdOnlyEnv)
			}
			if err := params.Run(cmd); err != nil {
				return err
			}
			params.PrintEnv(cmd)
			return nil
		},
	}

	cmd.Flags().StringVarP(&params.StoreRoot, "store", "s", "", "set store directory")
	cmd.Flags().StringVarP(&params.Operator, "operator", "o", "", "set operator name")
	cmd.Flags().StringVarP(&params.Account, "account", "a", "", "set account name")

	return cmd
}

func init() {
	env := createEnvCmd()
	GetRootCmd().AddCommand(env)
	env.AddCommand(createEnvMigrateCmd())

}

type SetContextParams struct {
	StoreRoot string
	Operator  string
	Account   string
}

func (p *SetContextParams) Run(cmd *cobra.Command) error {
	if *p == (SetContextParams{}) {
		// no edits
		return nil
	}
	current := GetConfig()
	if err := current.ContextConfig.Update(p.StoreRoot, p.Operator, p.Account); err != nil {
		return err
	}
	return current.Save()
}

func (p *SetContextParams) PrintEnv(cmd *cobra.Command) {
	conf := GetConfig()
	table := tablewriter.CreateTable()
	table.AddTitle("NSC Environment")
	table.AddHeaders("Setting", "Set", "Effective Value")
	table.AddRow("$"+NscCwdOnlyEnv, envSet(NscCwdOnlyEnv), "If set, default operator/account from cwd only")
	table.AddRow("$"+NscNoGitIgnoreEnv, envSet(NscNoGitIgnoreEnv), "If set, no .gitignore files written")
	table.AddRow("$"+store.NKeysPathEnv, envSet(store.NKeysPathEnv), AbbrevHomePaths(store.GetKeysDir()))
	table.AddRow("$"+NscHomeEnv, envSet(NscHomeEnv), AbbrevHomePaths(ConfigDirFlag))
	table.AddRow("$"+NscRootCasNatsEnv, envSet(NscRootCasNatsEnv),
		"If set, root CAs in the referenced file will be used for nats connections")
	table.AddRow("", "", "If not set, will default to the system trust store")
	table.AddRow("$"+NscTlsKeyNatsEnv, envSet(NscTlsKeyNatsEnv),
		"If set, the tls key in the referenced file will be used for nats connections")
	table.AddRow("$"+NscTlsCertNatsEnv, envSet(NscTlsCertNatsEnv),
		"If set, the tls cert in the referenced file will be used for nats connections")
	table.AddSeparator()

	table.AddRow("From CWD", "", yn(GetCwdCtx() != nil))
	table.AddRow("Default Stores Dir", "", AbbrevHomePaths(DataDirFlag))
	r := conf.StoreRoot
	if r == "" {
		r = "Not Set"
	}
	table.AddRow("Current Store Dir", "", AbbrevHomePaths(r))
	table.AddRow("Current Operator", "", conf.Operator)
	table.AddRow("Current Account", "", conf.Account)
	caFile := rootCAsFile
	if caFile == "" {
		caFile = "Default: System Trust Store"
	} else {
		caFile = "File: " + caFile
	}
	table.AddRow("Root CAs to trust", "", caFile)
	cmd.Println(table.Render())
}

type EnvMigrateParams struct {
	Dir string
}

func createEnvMigrateCmd() *cobra.Command {
	var params EnvMigrateParams
	cmd := &cobra.Command{
		Use:           "migrate",
		Short:         "migrate nsc configuration directories",
		Args:          MaxArgs(0),
		SilenceErrors: false,
		SilenceUsage:  false,
		Example:       "migrate",
		RunE: func(cmd *cobra.Command, args []string) error {
			target := os.Getenv("XDG_DATA_HOME")
			if target == "" {
				home, err := homedir.Dir()
				if err != nil {
					return err
				}
				target = path.Join(home, ".local", "share")
			}
			cmd.Println(target)
			return nil
		},
	}
	defaultHome := os.Getenv("NSC_HOME")
	if defaultHome == "" {
		defaultHome = "~/.nsc"
	}
	cmd.Flags().StringVarP(&params.Dir, "directory", "s", defaultHome, "nsc home directory")

	return cmd
}
