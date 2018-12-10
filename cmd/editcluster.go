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
	"github.com/spf13/cobra"
)

func createEditClusterCmd() *cobra.Command {
	var params EditClusterParams
	cmd := &cobra.Command{
		Use:          "cluster",
		Short:        "Edit a cluster",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		Hidden:       true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}

			cmd.Printf("Success! - edited cluster %q\n", params.ClusterContextParams.Name)

			Write("--", FormatJwt("Account", params.token))

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

	cmd.Flags().StringSliceVar(&params.accounts, "trusted-accounts", nil, "set trusted account public keys")
	cmd.Flags().StringSliceVar(&params.operators, "trusted-operators", nil, "set trusted operator public keys")
	cmd.Flags().StringVar(&params.accountUrlTemplate, "account-url-template", "", "template url for retrieving account jwts by account id")
	cmd.Flags().StringVar(&params.operatorUrlTemplate, "operator-url-template", "", "template url for retrieving operator jwts by operator id")

	params.ClusterContextParams.BindFlags(cmd)
	params.TimeParams.BindFlags(cmd)

	return cmd
}

func init() {
	editCmd.AddCommand(createEditClusterCmd())
}

type EditClusterParams struct {
	ClusterContextParams
	SignerParams
	TimeParams
	claim               *jwt.ClusterClaims
	accountUrlTemplate  string
	accounts            []string
	operatorUrlTemplate string
	operators           []string
	token               string
	tags                []string
	rmTags              []string
}

func (p *EditClusterParams) SetDefaults(ctx ActionCtx) error {
	p.ClusterContextParams.SetDefaults(ctx)
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)

	if !InteractiveFlag && ctx.NothingToDo("start", "expiry", "trusted-accounts",
		"trusted-operators", "account-url-template", "operator-url-template", "tag", "rm-tag") {
		ctx.CurrentCmd().SilenceUsage = false
		return fmt.Errorf("specify an edit option")
	}
	return nil
}

func (p *EditClusterParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if err = p.ClusterContextParams.Edit(ctx); err != nil {
		return err
	}
	return nil
}

func (p *EditClusterParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.ClusterContextParams.Validate(ctx); err != nil {
		return err
	}

	p.claim, err = ctx.StoreCtx().Store.ReadClusterClaim(p.ClusterContextParams.Name)
	if err != nil {
		return err
	}
	return err
}

func (p *EditClusterParams) PostInteractive(ctx ActionCtx) error {
	var err error
	if err = p.TimeParams.Edit(); err != nil {
		return err
	}

	if err := p.SignerParams.Edit(ctx); err != nil {
		return err
	}
	return nil
}

func (p *EditClusterParams) Validate(ctx ActionCtx) error {
	var err error
	if err = p.TimeParams.Validate(); err != nil {
		return err
	}
	if err = p.SignerParams.Resolve(ctx); err != nil {
		return err
	}
	return nil
}

func (p *EditClusterParams) Run(ctx ActionCtx) error {
	var err error
	if p.TimeParams.IsStartChanged() {
		p.claim.NotBefore, _ = p.TimeParams.StartDate()
	}

	if p.TimeParams.IsExpiryChanged() {
		p.claim.Expires, _ = p.TimeParams.ExpiryDate()
	}

	if ctx.CurrentCmd().Flag("account-url-template").Changed {
		p.claim.AccountURL = p.accountUrlTemplate
	}

	if ctx.CurrentCmd().Flag("operator-url-template").Changed {
		p.claim.OperatorURL = p.operatorUrlTemplate
	}

	if ctx.CurrentCmd().Flag("trusted-accounts").Changed {
		var accounts jwt.StringList
		accounts.Add(p.accounts...)
		p.claim.Accounts = accounts
	}

	if ctx.CurrentCmd().Flag("trusted-operators").Changed {
		var operators jwt.StringList
		operators.Add(p.operators...)
		p.claim.Trust = operators
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
