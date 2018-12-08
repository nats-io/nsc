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
		Use:          "server",
		Short:        "Add a server to a cluster (operator only)",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		Example:      `nsc add server -i`,
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
	cmd.Flags().StringVarP(&params.keyPath, "public-key", "k", "", "public key identifying the server")
	params.TimeParams.BindFlags(cmd)
	params.ClusterContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	addCmd.AddCommand(createAddServerCmd())
}

type AddServerParams struct {
	ClusterContextParams
	SignerParams
	TimeParams
	Entity
	clusterJwt string
}

func (p *AddServerParams) SetDefaults(ctx ActionCtx) error {
	p.ClusterContextParams.SetDefaults(ctx)
	p.SignerParams.SetDefaults(nkeys.PrefixByteCluster, false, ctx)
	p.create = true
	p.Entity.kind = nkeys.PrefixByteServer
	p.editFn = p.editServerClaim

	return nil
}

func (p *AddServerParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if err = p.ClusterContextParams.Edit(ctx); err != nil {
		return err
	}

	if err := p.Entity.Edit(); err != nil {
		return err
	}

	if err = p.TimeParams.Edit(); err != nil {
		return err
	}

	if err = p.SignerParams.Edit(ctx); err != nil {
		return err
	}

	return nil
}

func (p *AddServerParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.ClusterContextParams.Validate(ctx); err != nil {
		return err
	}

	d, err := ctx.StoreCtx().Store.Read(store.Clusters, p.ClusterContextParams.Name, store.JwtName(p.ClusterContextParams.Name))
	if err != nil {
		return err
	}
	p.clusterJwt = string(d)
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

	if err = p.SignerParams.Resolve(ctx); err != nil {
		return err
	}

	if err := p.TimeParams.Validate(); err != nil {
		return err
	}

	return p.Entity.Valid()
}

func (p *AddServerParams) Run(ctx ActionCtx) error {

	if err := p.Entity.StoreKeys(p.ClusterContextParams.Name); err != nil {
		return err
	}

	if err := p.Entity.GenerateClaim(p.signerKP, ctx); err != nil {
		return err
	}

	return nil
}

func (p *AddServerParams) editServerClaim(c interface{}, ctx ActionCtx) error {
	sc, ok := c.(*jwt.ServerClaims)
	if !ok {
		return errors.New("unable to cast to server claim")
	}

	sc.Cluster = p.clusterJwt

	if p.TimeParams.IsStartChanged() {
		sc.NotBefore, _ = p.TimeParams.StartDate()
	}

	if p.TimeParams.IsExpiryChanged() {
		sc.Expires, _ = p.TimeParams.ExpiryDate()
	}

	return nil
}
