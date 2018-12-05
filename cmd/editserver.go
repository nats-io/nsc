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
	"sort"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createEditServerCmd() *cobra.Command {
	var params EditServerParams
	cmd := &cobra.Command{
		Use:          "server",
		Short:        "Edit a server",
		Args:         cobra.MaximumNArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}

			cmd.Printf("Success! - edited server %q\n", params.name)

			Write("--", FormatJwt("Server", params.token))

			if params.claim.NotBefore > 0 {
				cmd.Printf("Token valid on %s - %s\n",
					UnixToDate(params.claim.NotBefore),
					HumanizedDate(params.claim.NotBefore))
			}
			if params.claim.Expires > 0 {
				cmd.Printf("Token expires on %s - %s\n",
					UnixToDate(params.claim.Expires),
					HumanizedDate(params.claim.Expires))
			}

			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&params.tags, "tag", "", nil, "add tags for user - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.rmTags, "rm-tag", "", nil, "remove tag - comma separated list or option can be specified multiple times")
	cmd.Flags().StringVarP(&params.name, "name", "n", "", "user name")
	cmd.Flags().StringVarP(&params.out, "output-file", "o", "", "output file '--' is stdout")

	params.ClusterContextParams.BindFlags(cmd)
	params.TimeParams.BindFlags(cmd)

	return cmd
}

func init() {
	editCmd.AddCommand(createEditServerCmd())
}

type EditServerParams struct {
	ClusterContextParams
	SignerParams
	TimeParams
	claim      *jwt.ServerClaims
	name       string
	token      string
	clusterJwt string
	out        string
	rmTags     []string
	tags       []string
}

func (p *EditServerParams) SetDefaults(ctx ActionCtx) error {
	p.ClusterContextParams.SetDefaults(ctx)
	p.SignerParams.SetDefaults(nkeys.PrefixByteCluster, true, ctx)

	if !InteractiveFlag && ctx.NothingToDo("start", "expiry", "tag", "rm-tag") {
		ctx.CurrentCmd().SilenceUsage = false
		return fmt.Errorf("specify an edit option")
	}
	return nil
}

func (p *EditServerParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if err = p.ClusterContextParams.Edit(ctx); err != nil {
		return err
	}

	if p.name == "" {
		p.name, err = ctx.StoreCtx().PickServer(p.ClusterContextParams.Name)
		if err != nil {
			return err
		}
	}

	if err = p.TimeParams.Edit(); err != nil {
		return err
	}

	if err = p.SignerParams.Edit(ctx); err != nil {
		return err
	}

	return nil
}

func (p *EditServerParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.ClusterContextParams.Validate(ctx); err != nil {
		return err
	}

	if p.name == "" {
		n := ctx.StoreCtx().DefaultServer(p.ClusterContextParams.Name)
		if n != nil {
			p.name = *n
		}
	}

	if p.name == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return fmt.Errorf("server name is required")
	}

	if !ctx.StoreCtx().Store.Has(store.Clusters, p.ClusterContextParams.Name, store.Servers, store.JwtName(p.name)) {
		return fmt.Errorf("server %q not found", p.name)
	}

	d, err := ctx.StoreCtx().Store.Read(store.Clusters, p.ClusterContextParams.Name, store.JwtName(p.ClusterContextParams.Name))
	if err != nil {
		return fmt.Errorf("error loading %q cluster jwt: %v", p.ClusterContextParams.Name, err)
	}
	p.clusterJwt = string(d)

	p.claim, err = ctx.StoreCtx().Store.ReadServerClaim(p.ClusterContextParams.Name, p.name)
	if err != nil {
		return err
	}
	return err
}

func (p *EditServerParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *EditServerParams) Validate(ctx ActionCtx) error {
	var err error
	if err = p.TimeParams.Validate(); err != nil {
		return err
	}
	if err = p.SignerParams.Resolve(ctx); err != nil {
		return err
	}
	return nil
}

func (p *EditServerParams) Run(ctx ActionCtx) error {
	var err error
	p.claim.Cluster = p.clusterJwt

	if p.TimeParams.IsStartChanged() {
		p.claim.NotBefore, _ = p.TimeParams.StartDate()
	}

	if p.TimeParams.IsExpiryChanged() {
		p.claim.Expires, _ = p.TimeParams.ExpiryDate()
	}

	p.claim.Tags.Add(p.tags...)
	p.claim.Tags.Remove(p.rmTags...)
	sort.Strings(p.claim.Tags)

	p.token, err = p.claim.Encode(p.signerKP)
	if err != nil {
		return err
	}
	return ctx.StoreCtx().Store.StoreClaim([]byte(p.token))
}
