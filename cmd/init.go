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

	"github.com/xlab/tablewriter"

	"github.com/nats-io/nsc/cli"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createInitCmd() *cobra.Command {
	var p InitParams
	cmd := &cobra.Command{
		Use:           "init",
		Short:         "init a configuration directory",
		Example:       "init --name project --dir nats/projectdir",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, _ := getStore()
			if s != nil {
				return fmt.Errorf("%q is already a store", s.Dir)
			}

			p.SetDefaults()

			if err := p.Interactive(cmd); err != nil {
				return err
			}

			if err := p.Validate(); err != nil {
				return err
			}

			if err := p.Run(); err != nil {
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
					table.AddRow(c.name, store.KeyTypeLabel(c.kind), c.keyPath)
				}
			}

			if printed {
				cmd.Println(cli.Wrap(70, "Project initialization generated NKeys. These keys should be treated as secrets.",
					"You can move the directory, and reference them from the",
					fmt.Sprintf("`$%s`", store.NKeysPathEnv), "environment variable. To remind yourself of current environment",
					"configuration type `nsc env` while in a project directory.\n"))
				cmd.Println(table.Render())
			}

			cmd.Println("Success! - initialized project directory")

			return nil
		},
	}

	cmd.Flags().BoolVarP(&p.defaults, "yes", "y", false, "generate all defaults and skip questions")

	cmd.Flags().StringVarP(&p.name, "name", "n", "", "name for the configuration environment, if not specified uses <dirname>")

	cmd.Flags().StringVarP(&p.Container.name, "operator-name", "", "", "operator name (default '<name>_operator')")
	cmd.Flags().StringVarP(&p.Container.keyPath, "operator-key", "", "", "operator keypath or seed value (default generated)")
	cmd.Flags().BoolVarP(&p.Container.create, "create-operator", "", true, "create an operator")

	cmd.Flags().StringVarP(&p.account.name, "account-name", "", "", "name for the account (default '<name>_account')")
	cmd.Flags().StringVarP(&p.account.keyPath, "account-key", "", "", "account keypath or seed value (default generated)")
	cmd.Flags().BoolVarP(&p.account.create, "create-account", "", true, "create an account")

	cmd.Flags().StringVarP(&p.user.name, "user-name", "", "", "name for the user (default '<name>_user')")
	cmd.Flags().StringVarP(&p.user.keyPath, "user-key", "", "", "user keypath or seed value (default generated)")
	cmd.Flags().BoolVarP(&p.user.create, "create-user", "", true, "create an user")

	cmd.Flags().StringVarP(&p.cluster.name, "cluster-name", "", "", "name for the cluster (default '<name>_cluster')")
	cmd.Flags().StringVarP(&p.cluster.keyPath, "cluster-key", "", "", "cluster keypath or seed value (default generated)")
	cmd.Flags().BoolVarP(&p.cluster.create, "create-cluster", "", false, "create a cluster")

	cmd.Flags().StringVarP(&p.server.name, "server-name", "", "", "name for the server (default '<name>_server')")
	cmd.Flags().StringVarP(&p.server.keyPath, "server-key", "", "", "server keypath or seed value (default generated)")
	cmd.Flags().BoolVarP(&p.server.create, "create-server", "", false, "create a server")

	cmd.Flags().MarkHidden("create-account")
	cmd.Flags().MarkHidden("create-operator")
	cmd.Flags().MarkHidden("create-user")

	return cmd
}

func init() {
	rootCmd.AddCommand(createInitCmd())
}

type InitParams struct {
	defaults bool
	Container
	account Container
	cluster Container
	server  Container
	user    Container
}

func (p *InitParams) Containers() []*Container {
	return []*Container{&p.Container, &p.account, &p.user, &p.cluster, &p.server}
}

func ValidateNkey(kind nkeys.PrefixByte) cli.Validator {
	return func(v string) error {
		nk, err := store.ResolveKey(v)
		if err != nil {
			return err
		}
		t, err := store.KeyType(nk)
		if err != nil {
			return err
		}
		if t != kind {
			return fmt.Errorf("specified key is not valid for an %s", store.KeyTypeLabel(kind))
		}
		return nil
	}
}

func (p *InitParams) SetDefaults() error {
	var err error

	p.kind = nkeys.PrefixByteOperator
	p.account.kind = nkeys.PrefixByteAccount
	p.cluster.kind = nkeys.PrefixByteCluster
	p.server.kind = nkeys.PrefixByteServer
	p.user.kind = nkeys.PrefixByteUser

	p.dir, err = os.Getwd()
	if err != nil {
		return err
	}
	base := filepath.Base(p.dir)

	// set the operator name
	if p.name == "" {
		p.name = fmt.Sprintf("%s_operator", base)
	}

	if p.account.name == "" {
		p.account.name = fmt.Sprintf("%s_account", base)
	}

	if p.user.name == "" {
		p.user.name = fmt.Sprintf("%s_user", base)
	}

	if p.cluster.name == "" {
		p.cluster.name = fmt.Sprintf("%s_cluster", base)
	}

	if p.server.name == "" {
		p.server.name = "localhost"
	}
	return nil
}

func (p *InitParams) Interactive(cmd *cobra.Command) error {
	if p.defaults {
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

	if err := p.Container.Edit(); err != nil {
		return err
	}

	if err := p.account.Edit(); err != nil {
		return err
	}

	if err := p.user.Edit(); err != nil {
		return err
	}

	if err := p.cluster.Edit(); err != nil {
		return err
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
			p.Container.Edit()
		case 3:
			p.account.Edit()
		case 4:
			p.user.Edit()
		case 5:
			p.cluster.Edit()
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
	table.AddRow("Operator", p.Container.name, p.Container.KeySource())
	table.AddRow("Account", p.account.name, p.account.KeySource())
	table.AddRow("User", p.user.name, p.user.KeySource())
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
	containers := p.Containers()
	for _, e := range containers {
		if err := e.StoreKeys(p.name); err != nil {
			return err
		}
	}

	_, err := store.CreateStore(p.dir, p.name, p.Container.kp)
	if err != nil {
		return err
	}

	for i, c := range containers {
		if i == 0 {
			// operator container is created by the store
			continue
		}
		c.GenerateClaim(containers[i-1].kp)
	}

	return nil
}

type Container struct {
	create    bool
	dir       string
	generated bool
	keyPath   string
	kind      nkeys.PrefixByte
	kp        nkeys.KeyPair
	name      string
}

func (c *Container) Valid() error {
	var err error
	if c.keyPath != "" {
		c.kp, err = store.ResolveKey(c.keyPath)
		if err != nil {
			return err
		}

		if !store.KeyPairTypeOk(c.kind, c.kp) {
			return fmt.Errorf("invalid %s key", store.KeyTypeLabel(c.kind))
		}

	} else {
		c.kp, err = store.CreateNKey(c.kind)
		if err != nil {
			return err
		}
		c.generated = true
	}
	return nil
}

func (c *Container) StoreKeys(root string) error {
	var err error
	if c.create && c.keyPath == "" {
		ks := store.NewKeyStore()
		if c.keyPath, err = ks.Store(root, c.name, c.kp); err != nil {
			return err
		}
	}
	return nil
}

func (c *Container) KeySource() string {
	if c.keyPath == "" {
		return "Generated"
	}
	return c.keyPath
}

func (c *Container) Edit() error {
	var err error
	label := store.KeyTypeLabel(c.kind)

	if c.kind == nkeys.PrefixByteCluster || c.kind == nkeys.PrefixByteServer {
		c.create, err = cli.PromptNY(fmt.Sprintf("create a %s", label))
		if err != nil {
			return err
		}
		if !c.create {
			return nil
		}
	}

	c.name, err = cli.Prompt(fmt.Sprintf("%s name", label), c.name, true, cli.LengthValidator(1))
	if err != nil {
		return err
	}

	ok, err := cli.PromptYN(fmt.Sprintf("generate an %s nkey", label))
	if err != nil {
		return err
	}
	if !ok {
		c.keyPath, err = cli.Prompt(fmt.Sprintf("path to the %s nkey", label), "",
			true, ValidateNkey(c.kind))
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Container) GenerateClaim(signer nkeys.KeyPair) error {
	if !c.create {
		return nil
	}
	pk, err := c.kp.PublicKey()
	if err != nil {
		return err
	}
	pub := string(pk)
	var claim jwt.Claims
	switch c.kind {
	case nkeys.PrefixByteOperator:
		claim = jwt.NewOperatorClaims(pub)
	case nkeys.PrefixByteAccount:
		claim = jwt.NewAccountClaims(pub)
	case nkeys.PrefixByteUser:
		claim = jwt.NewUserClaims(pub)
	case nkeys.PrefixByteCluster:
		claim = jwt.NewClusterClaims(pub)
	case nkeys.PrefixByteServer:
		claim = jwt.NewServerClaims(pub)
	}
	cd := claim.Claims()
	cd.Name = c.name
	token, err := claim.Encode(signer)
	if err != nil {
		return err
	}
	s, err := getStore()
	if err != nil {
		return err
	}
	return s.StoreClaim([]byte(token))
}
