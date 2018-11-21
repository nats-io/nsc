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

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/spf13/cobra"
)

func createEditAccount() *cobra.Command {
	var params EditAccountParams
	cmd := &cobra.Command{
		Use:          "account",
		Short:        "Edit an account",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}

			cmd.Printf("Success! - edited account %q\n", params.AccountContextParams.Name)

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
	params.AccountContextParams.BindFlags(cmd)
	params.TimeParams.BindFlags(cmd)

	return cmd
}

func init() {
	editCmd.AddCommand(createEditAccount())
}

type EditAccountParams struct {
	AccountContextParams
	claim *jwt.AccountClaims
	SignerParams
	TimeParams
	token string
}

func (p *EditAccountParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.SetDefaults(ctx)
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)

	if !InteractiveFlag && ctx.NothingToDo("start", "expiry") {
		return fmt.Errorf("specify an edit option")
	}
	return nil
}

func (p *EditAccountParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}
	return nil
}

func (p *EditAccountParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	p.claim, err = ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		return err
	}
	return err
}

func (p *EditAccountParams) PostInteractive(ctx ActionCtx) error {
	var err error
	if err = p.TimeParams.Edit(); err != nil {
		return err
	}

	if err := p.SignerParams.Edit(ctx); err != nil {
		return err
	}
	return nil
}

func (p *EditAccountParams) Validate(ctx ActionCtx) error {
	var err error
	if err = p.TimeParams.Validate(); err != nil {
		return err
	}
	if err = p.SignerParams.Resolve(ctx); err != nil {
		return err
	}
	return nil
}

func (p *EditAccountParams) Run(ctx ActionCtx) error {
	var err error
	if p.TimeParams.IsStartChanged() {
		p.claim.NotBefore, _ = p.TimeParams.StartDate()
	}

	if p.TimeParams.IsExpiryChanged() {
		p.claim.Expires, _ = p.TimeParams.ExpiryDate()
	}

	p.token, err = p.claim.Encode(p.signerKP)
	if err != nil {
		return err
	}
	return ctx.StoreCtx().Store.StoreClaim([]byte(p.token))
}
