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

	"github.com/nats-io/nkeys"
	"github.com/spf13/cobra"
)

type CreateCombiParams struct {
	name     string
	dir      string
	account  CreateAccountParams
	operator CreateOperatorParams
	cluster  CreateOperatorParams
}

func (p *CreateCombiParams) InitAccount() error {
	var err error

	if p.account.name == "" {
		p.account.name = fmt.Sprintf("account_%s", p.name)
	}

	p.account.dir = filepath.Join(p.dir, "accounts", p.name)

	if p.account.keyFile == "" {
		p.account.kp, err = nkeys.CreateAccount()
		if err != nil {
			return err
		}
	}
	return p.account.Validate()
}

func (p *CreateCombiParams) InitCluster() error {
	var err error

	if p.cluster.name == "" {
		p.cluster.name = fmt.Sprintf("cluster_%s", p.name)
	}

	p.cluster.dir = filepath.Join(p.dir, "clusters", p.name)

	if p.cluster.keyFile == "" {
		p.cluster.kp, err = nkeys.CreateCluster()
		if err != nil {
			return err
		}
	}

	return p.cluster.Validate()
}

func (p *CreateCombiParams) InitOperator() error {
	var err error

	if p.operator.name == "" {
		p.operator.name = fmt.Sprintf("operator_%s", p.name)
	}

	p.operator.dir = filepath.Join(p.dir, "operator")

	if p.operator.keyFile == "" {
		p.operator.kp, err = nkeys.CreateOperator()
		if err != nil {
			return err
		}
	}

	return p.operator.Validate()
}

func (p *CreateCombiParams) Validate() error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	if !filepath.IsAbs(p.dir) {
		p.dir = filepath.Join(dir, p.dir)
	}

	if p.name == "" {
		p.name = filepath.Base(p.dir)
	}

	if err := p.InitOperator(); err != nil {
		return err
	}

	if err := p.InitCluster(); err != nil {
		return err
	}

	if err := p.InitAccount(); err != nil {
		return err
	}

	return nil
}

func (p *CreateCombiParams) Run() error {
	if err := os.MkdirAll(p.dir, 0700); err != nil {
		return err
	}

	if err := os.MkdirAll(p.operator.dir, 0700); err != nil {
		return err
	}

	if err := os.MkdirAll(p.cluster.dir, 0700); err != nil {
		return err
	}

	if err := os.MkdirAll(p.account.dir, 0700); err != nil {
		return err
	}

	if err := p.operator.Run(); err != nil {
		return err
	}

	if err := p.cluster.Run(); err != nil {
		return err
	}

	if err := p.account.Run(); err != nil {
		return err
	}

	return nil
}

func createCombiCmd() *cobra.Command {
	var p CreateCombiParams
	cmd := &cobra.Command{
		Use:     "combi",
		Short:   "Create an combi configuration directory - combi has layout for operator, accounts and cluster",
		Example: "create combi --name mycombi <dirpath>",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				p.dir = "."
			}
			if len(args) == 1 {
				p.dir = args[0]
			}

			if err := p.Validate(); err != nil {
				return err
			}

			if err := p.Run(); err != nil {
				return err
			}

			if p.operator.keyFile != "" {
				cmd.Printf("Generated operator key - private key stored %q\n", p.operator.keyFile)
			}

			if p.cluster.keyFile != "" {
				cmd.Printf("Generated cluster key - private key stored %q\n", p.cluster.keyFile)
			}

			if p.account.keyFile != "" {
				cmd.Printf("Generated account key - private key stored %q\n", p.account.keyFile)
			}

			cmd.Printf("Success! - created combi directory %q\n", p.dir)

			return nil
		},
	}

	cmd.Flags().StringVarP(&p.name, "name", "n", "", "name for the combi, if not specified uses <dirname>")
	cmd.Flags().StringVarP(&p.operator.name, "operator-name", "", "", "name for the operator, if not specified uses operator")
	cmd.Flags().StringVarP(&p.operator.keyFile, "operator-key", "", "", "operator keypath or seed value, generated if not specified")
	cmd.Flags().StringVarP(&p.account.name, "account-name", "", "", "name for the operator, if not specified uses account")
	cmd.Flags().StringVarP(&p.account.keyFile, "account-key", "", "", "account keypath or seed value, generated if not specified")
	cmd.Flags().StringVarP(&p.cluster.name, "cluster-name", "", "", "name for the cluster, if not specified uses cluster")
	cmd.Flags().StringVarP(&p.cluster.keyFile, "cluster-key", "", "", "cluster keypath or seed value, generated if not specified")

	return cmd
}

func init() {
	createCmd.AddCommand(createCombiCmd())
}
