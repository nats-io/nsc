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

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createAddServerCmd() *cobra.Command {
	var params AddServerParams
	cmd := &cobra.Command{
		Use:           "server",
		Short:         "Add a server to a cluster (operator only)",
		SilenceErrors: true,
		SilenceUsage:  true,
		Example: `nsc add server -i
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}

			if params.generated {
				cmd.Printf("Generated server key - private key stored %q\n", params.keyPath)
			}

			cmd.Printf("Success! - added server %q\n", params.name)
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.name, "name", "n", "", "server name")
	cmd.Flags().StringVarP(&params.clusterName, "cluster", "", "", "cluster name")
	cmd.Flags().StringVarP(&params.keyPath, "public-key", "k", "", "public key identifying the server")
	params.TimeParams.BindFlags(cmd)

	return cmd
}

func init() {
	addCmd.AddCommand(createAddServerCmd())
}

type AddServerParams struct {
	TimeParams
	Entity
	clusterKP   nkeys.KeyPair
	clusterName string
}

func (p *AddServerParams) SetDefaults(ctx ActionCtx) error {
	p.create = true
	p.kind = nkeys.PrefixByteServer
	p.editFn = p.editServerClaim
	return nil
}

func (p *AddServerParams) PreInteractive(ctx ActionCtx) error {
	var err error

	if err := p.Entity.Edit(); err != nil {
		return err
	}

	p.clusterName, err = ctx.StoreCtx().PickCluster(p.clusterName)
	if err != nil {
		return err
	}

	if err = p.TimeParams.Edit(); err != nil {
		return err
	}

	p.clusterKP, err = ctx.StoreCtx().ResolveKey(nkeys.PrefixByteCluster, KeyPathFlag)
	if err != nil {
		return err
	}

	if p.clusterKP == nil {
		err = EditKeyPath(nkeys.PrefixByteAccount, "cluster keypath", &KeyPathFlag)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *AddServerParams) Load(ctx ActionCtx) error {
	return nil
}

func (p *AddServerParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *AddServerParams) Validate(ctx ActionCtx) error {
	var err error
	if p.name == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return fmt.Errorf("server name is required")
	}

	if p.clusterName == "" {
		// default account was not found by get context, so we either we have none or many
		accounts, err := ctx.StoreCtx().Store.ListSubContainers(store.Clusters)
		if err != nil {
			return err
		}
		c := len(accounts)
		if c == 0 {
			return errors.New("no clusters defined - add cluster first")
		} else {
			return errors.New("multiple clusters found - specify --cluster or navigate to a cluster directory")
		}
	}

	p.clusterKP, err = ctx.StoreCtx().ResolveKey(nkeys.PrefixByteCluster, KeyPathFlag)
	if err != nil {
		return err
	}

	if err := p.TimeParams.Validate(); err != nil {
		return err
	}

	return p.Entity.Valid()
}

func (p *AddServerParams) Run(ctx ActionCtx) error {

	if err := p.Entity.StoreKeys(p.clusterName); err != nil {
		return err
	}

	if err := p.Entity.GenerateClaim(p.clusterKP); err != nil {
		return err
	}

	return nil
}

func (p *AddServerParams) editServerClaim(c interface{}) error {
	sc, ok := c.(*jwt.ServerClaims)
	if !ok {
		return errors.New("unable to cast to server claim")
	}

	if p.TimeParams.IsStartChanged() {
		sc.NotBefore, _ = p.TimeParams.StartDate()
	}

	if p.TimeParams.IsExpiryChanged() {
		sc.Expires, _ = p.TimeParams.ExpiryDate()
	}

	return nil
}
