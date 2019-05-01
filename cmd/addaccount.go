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
	"errors"
	"fmt"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/spf13/cobra"
)

func CreateAddAccountCmd() *cobra.Command {
	var params AddAccountParams
	cmd := &cobra.Command{
		Use:          "account",
		Short:        "Add an account",
		Args:         MaxArgs(0),
		SilenceUsage: true,

		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}
			if params.generated && !QuietMode() {
				cmd.Printf("Generated account key - private key stored %q\n", AbbrevHomePaths(params.keyPath))
			}

			if !QuietMode() {
				cmd.Printf("Success! - added account %q\n", params.name)
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&params.name, "name", "n", "", "account name")
	cmd.Flags().StringVarP(&params.keyPath, "public-key", "k", "", "public key identifying the account")
	params.TimeParams.BindFlags(cmd)

	return cmd
}

func init() {
	addCmd.AddCommand(CreateAddAccountCmd())
}

type AddAccountParams struct {
	Entity
	SignerParams
	TimeParams
}

func (p *AddAccountParams) SetDefaults(ctx ActionCtx) error {
	p.create = true
	p.Entity.kind = nkeys.PrefixByteAccount
	p.editFn = p.editAccount
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)
	return nil
}

func (p *AddAccountParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if err = p.Entity.Edit(); err != nil {
		return err
	}

	if err = p.TimeParams.Edit(); err != nil {
		return err
	}

	if err := p.SignerParams.Edit(ctx); err != nil {
		return err
	}

	return nil
}

func (p *AddAccountParams) Load(ctx ActionCtx) error {
	return nil
}

func (p *AddAccountParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *AddAccountParams) Validate(ctx ActionCtx) error {
	var err error
	if p.name == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return fmt.Errorf("account name is required")
	}

	if err = p.TimeParams.Validate(); err != nil {
		return err
	}

	if err := p.Resolve(ctx); err != nil {
		return err
	}

	return p.Valid()
}

func (p *AddAccountParams) Run(ctx ActionCtx) error {
	if err := p.Entity.StoreKeys(ctx.StoreCtx().Store.GetName()); err != nil {
		return err
	}
	if err := p.Entity.GenerateClaim(p.signerKP, ctx); err != nil {
		return err
	}

	// if we added an account - make this the current account
	return GetConfig().SetAccount(p.Entity.name)
}

func (p *AddAccountParams) editAccount(c interface{}, ctx ActionCtx) error {
	ac, ok := c.(*jwt.AccountClaims)
	if !ok {
		return errors.New("unable to cast to account claim")
	}

	if p.TimeParams.IsStartChanged() {
		ac.NotBefore, _ = p.TimeParams.StartDate()
	}

	if p.TimeParams.IsExpiryChanged() {
		ac.Expires, _ = p.TimeParams.ExpiryDate()
	}

	return nil
}
