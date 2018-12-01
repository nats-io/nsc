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
	"path/filepath"

	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
	"github.com/xlab/tablewriter"
)

func CreateInitCmd() *cobra.Command {
	var p InitParams
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Init a configuration directory",
		Example: `init --name operatorname
init --interactive
`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {

			p.SetDefaults()

			if err := p.Interactive(cmd); err != nil {
				return err
			}

			if err := p.Validate(); err != nil {
				return err
			}

			if err := p.Run(); err != nil {
				fmt.Printf("%v\n", err)
				return err
			}

			cmd.Println()

			table := tablewriter.CreateTable()
			table.UTF8Box()
			table.AddTitle("Generated NKeys Location")
			table.AddHeaders("Name", "Kind", "Location")
			printed := false
			for _, c := range p.Containers() {
				if c.create && c.generated {
					printed = true
					table.AddRow(c.name, c.kind.String(), c.keyPath)
				}
			}

			if printed {
				cmd.Println(cli.Wrap(70, "Project initialization generated NKeys.",
					"These keys should be treated as secrets.", "You can move the directory,",
					"and reference them from the", fmt.Sprintf("`$%s`", store.NKeysPathEnv),
					"environment variable. To remind yourself of current environment",
					"configuration type `nsc env` while in a project directory.\n"))
				cmd.Println(table.Render())
			}

			cmd.Println("Success! - initialized project directory")

			return nil
		},
	}

	cmd.Flags().StringVarP(&p.environmentName, "name", "n", "test", "name for the configuration environment")

	cmd.Flags().StringVarP(&p.operator.name, "operator-name", "", "", "operator name (default '<name>_operator')")
	cmd.Flags().StringVarP(&p.operator.keyPath, "operator-key", "", "", "operator keypath (default generated)")
	cmd.Flags().BoolVarP(&p.operator.create, "create-operator", "", true, "create an operator")

	cmd.Flags().StringVarP(&p.account.name, "account-name", "", "", "name for the account (default '<name>_account')")
	cmd.Flags().StringVarP(&p.account.keyPath, "account-key", "", "", "account keypath (default generated)")
	cmd.Flags().BoolVarP(&p.account.create, "create-account", "", true, "create an account")

	cmd.Flags().StringVarP(&p.user.name, "user-name", "", "", "name for the user (default '<name>_user')")
	cmd.Flags().StringVarP(&p.user.keyPath, "user-key", "", "", "user keypath (default generated)")
	cmd.Flags().BoolVarP(&p.user.create, "create-user", "", true, "create an user")

	cmd.Flags().StringVarP(&p.cluster.name, "cluster-name", "", "", "name for the cluster (default '<name>_cluster')")
	cmd.Flags().StringVarP(&p.cluster.keyPath, "cluster-key", "", "", "cluster keypath (default generated)")
	cmd.Flags().BoolVarP(&p.cluster.create, "create-cluster", "", false, "create a cluster")

	cmd.Flags().StringVarP(&p.server.name, "server-name", "", "localhost", "name for the server")
	cmd.Flags().StringVarP(&p.server.keyPath, "server-key", "", "", "server keypath (default generated)")
	cmd.Flags().BoolVarP(&p.server.create, "create-server", "", false, "create a server")

	cmd.Flags().MarkHidden("create-account")
	cmd.Flags().MarkHidden("create-operator")
	cmd.Flags().MarkHidden("create-user")

	return cmd
}

func init() {
	GetRootCmd().AddCommand(CreateInitCmd())
}

type InitParams struct {
	storeRoot       string
	environmentName string
	operator        Entity
	account         Entity
	cluster         Entity
	server          Entity
	user            Entity
}

func (p *InitParams) Containers() []*Entity {
	return []*Entity{&p.operator, &p.account, &p.user, &p.cluster, &p.server}
}

func (p *InitParams) SetDefaults() error {
	p.operator.kind = nkeys.PrefixByteOperator
	p.account.kind = nkeys.PrefixByteAccount
	p.cluster.kind = nkeys.PrefixByteCluster
	p.server.kind = nkeys.PrefixByteServer
	p.user.kind = nkeys.PrefixByteUser

	var err error
	p.storeRoot, err = filepath.Abs(GetConfig().StoreRoot)
	if err != nil {
		return fmt.Errorf("error calculating the absolute filepath for %q: %v", p.storeRoot, err)
	}

	// if defaults are set we are not prompting
	if p.environmentName == "" {
		p.environmentName = "test"
	}
	if !InteractiveFlag {
		p.SetDefaultNames()
	}
	return nil
}

func (p *InitParams) SetDefaultNames() {
	// set the operator name
	if p.operator.name == "" {
		p.operator.name = fmt.Sprintf("%s_operator", p.environmentName)
	}

	if p.account.name == "" {
		p.account.name = fmt.Sprintf("%s_account", p.environmentName)
	}

	if p.user.name == "" {
		p.user.name = fmt.Sprintf("%s_user", p.environmentName)
	}

	if p.cluster.name == "" {
		p.cluster.name = fmt.Sprintf("%s_cluster", p.environmentName)
	}

	if p.server.name == "" {
		p.server.name = "localhost"
	}
}

func (p *InitParams) Interactive(cmd *cobra.Command) error {
	var err error
	if !InteractiveFlag {
		return nil
	}
	m := cli.Wrap(70, "The nsc utility will walk you through creating a JWT-based NATS project.",
		"NATS JWT projects are account isolated and use NKeys to authenticate to the server.",
		"Clients authenticate to the server by signing a nonce and providing an `user configuration`",
		"in the form of a JWT. For more information please refer to the NATS documentation.\n")
	cmd.Println(m)

	m = cli.Wrap(70, "This init session only covers the most common options, and tries to ",
		"guess sensible defaults. The process will guide you through the process of creating an operator,",
		"account, and user.\n")
	cmd.Println(m)

	m = cli.Wrap(70, "Entities, such as operators, accounts, users, clusters, and",
		"servers are individually identified by NKeys (Ed25519 public key signature). You can choose",
		"to specify an key or have nsc generate them for you.\n")
	cmd.Println(m)

	p.environmentName, err = cli.Prompt("environment name", p.environmentName, true, cli.LengthValidator(1))
	if err != nil {
		return err
	}

	p.SetDefaultNames()

	if err := p.operator.Edit(); err != nil {
		return err
	}

	if err := p.account.Edit(); err != nil {
		return err
	}

	if err := p.user.Edit(); err != nil {
		return err
	}

	p.cluster.create, err = cli.PromptBoolean(fmt.Sprintf("create a %s", nkeys.PrefixByteCluster.String()), false)
	if err != nil {
		return err
	}
	if p.cluster.create {
		if err := p.cluster.Edit(); err != nil {
			return err
		}
	}
	if p.cluster.create {
		if err := p.server.Edit(); err != nil {
			return err
		}
	}

	for {
		p.PrintSummary(cmd)
		choices := []string{"Yes", "Cancel", "Edit operator", "Edit account", "Edit user", "Edit cluster", "Edit server"}
		c, err := cli.PromptChoices("is this OK", choices)
		if err != nil {
			return err
		}
		switch c {
		case 0:
			return nil
		case 1:
			return fmt.Errorf("cancelled")
		case 2:
			p.operator.Edit()
		case 3:
			p.account.Edit()
		case 4:
			p.user.Edit()
		case 5:
			p.cluster.Edit()
			if !p.cluster.create {
				p.server.create = false
			}
		case 6:
			p.server.Edit()
		}
	}
}

func (p *InitParams) PrintSummary(cmd *cobra.Command) {
	table := tablewriter.CreateTable()
	table.UTF8Box()
	table.AddTitle("Project Options")
	table.AddHeaders("Entity", "Name", "NKey")
	if p.operator.create {
		table.AddRow("Operator", p.operator.name, p.operator.KeySource())
	}
	if p.account.create {
		table.AddRow("Account", p.account.name, p.account.KeySource())
	}
	if p.user.create {
		table.AddRow("User", p.user.name, p.user.KeySource())
	}
	if p.cluster.create {
		table.AddRow("Cluster", p.cluster.name, p.cluster.KeySource())
	} else {
		table.AddRow("Cluster - skipped", "", "")
	}
	if p.server.create {
		table.AddRow("Server", p.server.name, p.server.KeySource())
	} else {
		table.AddRow("Server - skipped", "", "")
	}
	cmd.Println(table.Render())
}

func (p *InitParams) Validate() error {
	for _, e := range p.Containers() {
		if err := e.Valid(); err != nil {
			return err
		}
	}
	return nil
}

func (p *InitParams) Run() error {
	var operator *store.NamedKey
	if p.operator.create {
		operator = &store.NamedKey{Name: p.operator.name, KP: p.operator.kp}
	}
	_, err := store.CreateStore(p.environmentName, p.storeRoot, operator)
	if err != nil {
		return err
	}

	GetConfig().Operator = operator.Name
	if err := GetConfig().Save(); err != nil {
		return err
	}

	containers := p.Containers()
	for _, e := range containers {
		if !e.create {
			continue
		}
		var parent string
		switch e.kind {
		case nkeys.PrefixByteUser:
			parent = p.account.name
		case nkeys.PrefixByteServer:
			parent = p.cluster.name
		}

		if err := e.StoreKeys(parent); err != nil {
			return err
		}
	}

	for i, c := range containers {
		// operator container is created by the store - some flags may prevent creation
		if !c.create || i == 0 {
			continue
		}
		c.GenerateClaim(containers[i-1].kp, nil)
	}

	return nil
}
