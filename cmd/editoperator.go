/*
 *
 *  * Copyright 2018-2019 The NATS Authors
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package cmd

import (
	"fmt"
	"strings"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createEditOperator() *cobra.Command {
	var params EditOperatorParams
	cmd := &cobra.Command{
		Use:          "operator",
		Short:        "Edit an operator",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}

			cmd.Printf("Success! - edited operator\n")
			return Write("--", FormatJwt("Operator", params.token))
		},
	}
	params.signingKeys.BindFlags("sk", "", nkeys.PrefixByteOperator, cmd)
	cmd.Flags().StringSliceVarP(&params.rmSigningKeys, "rm-sk", "", nil, "remove signing key - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.tags, "tag", "", nil, "add tags for user - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.rmTags, "rm-tag", "", nil, "remove tag - comma separated list or option can be specified multiple times")
	cmd.Flags().StringVarP(&params.asu, "account-jwt-server-url", "u", "", "set account jwt server url for nsc sync (only http/https urls supported if updating with nsc)")
	params.TimeParams.BindFlags(cmd)

	return cmd
}

func init() {
	editCmd.AddCommand(createEditOperator())
}

type EditOperatorParams struct {
	SignerParams
	GenericClaimsParams
	claim         *jwt.OperatorClaims
	token         string
	asu           string
	signingKeys   SigningKeysParams
	rmSigningKeys []string
}

func (p *EditOperatorParams) SetDefaults(ctx ActionCtx) error {
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)

	if !InteractiveFlag && ctx.NothingToDo("sk", "rm-sk", "start", "expiry", "tag", "rm-tag", "account-jwt-server-url") {
		ctx.CurrentCmd().SilenceUsage = false
		return fmt.Errorf("specify an edit option")
	}
	return nil
}

func (p *EditOperatorParams) PreInteractive(ctx ActionCtx) error {
	return nil
}

func (p *EditOperatorParams) Load(ctx ActionCtx) error {
	var err error

	name := ctx.StoreCtx().Store.GetName()
	if !ctx.StoreCtx().Store.Has(store.JwtName(name)) {
		return fmt.Errorf("no operator %q found", name)
	}

	d, err := ctx.StoreCtx().Store.Read(store.JwtName(name))
	if err != nil {
		return err
	}

	oc, err := jwt.DecodeOperatorClaims(string(d))
	if err != nil {
		return err
	}

	if p.asu == "" {
		p.asu = oc.AccountServerURL
	}

	p.claim = oc
	return nil
}

func (p *EditOperatorParams) PostInteractive(ctx ActionCtx) error {
	var err error
	if err = p.GenericClaimsParams.Edit(); err != nil {
		return err
	}
	p.asu, err = cli.Prompt("account jwt server url", p.asu, true, nil)
	if err != nil {
		return err
	}
	p.asu = strings.TrimSpace(p.asu)
	return p.signingKeys.Edit()
}

func (p *EditOperatorParams) Validate(ctx ActionCtx) error {
	var err error
	if err = p.GenericClaimsParams.Valid(); err != nil {
		return err
	}
	if err = p.signingKeys.Valid(); err != nil {
		return err
	}
	if err = p.SignerParams.Resolve(ctx); err != nil {
		return err
	}
	return nil
}

func (p *EditOperatorParams) Run(ctx ActionCtx) error {
	var err error
	if err = p.GenericClaimsParams.Run(ctx, p.claim); err != nil {
		return err
	}
	keys, _ := p.signingKeys.PublicKeys()
	if len(keys) > 0 {
		p.claim.SigningKeys.Add(keys...)
	}
	p.claim.SigningKeys.Remove(p.rmSigningKeys...)

	p.claim.AccountServerURL = p.asu

	p.token, err = p.claim.Encode(p.signerKP)
	if err != nil {
		return err
	}
	return ctx.StoreCtx().Store.StoreClaim([]byte(p.token))
}
