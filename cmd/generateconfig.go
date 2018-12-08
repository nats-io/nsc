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

	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createGenerateConfigCmd() *cobra.Command {
	var params GenerateConfigParams
	cmd := &cobra.Command{
		Use:          "config",
		Short:        "Generate a config file for an user",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		Example:      `nsc generate config --account a --user u`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}
			if !QuietMode() && params.out != "--" {
				cmd.Printf("Success!! - generated %q\n", params.out)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.user, "user", "u", "", "name of the user")
	cmd.Flags().StringVarP(&params.out, "output-file", "o", "--", "output file '--' is stdout")
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	generateCmd.AddCommand(createGenerateConfigCmd())
}

type GenerateConfigParams struct {
	AccountContextParams
	kind      string
	user      string
	out       string
	entityKP  nkeys.KeyPair
	entityJwt []byte
}

func (p *GenerateConfigParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.SetDefaults(ctx)
	if p.user == "" {
		if p.AccountContextParams.Name != "" {
			entries, err := ctx.StoreCtx().Store.ListEntries(store.Accounts, p.AccountContextParams.Name, store.Users)
			if err != nil {
				return err
			}
			switch len(entries) {
			case 0:
				return fmt.Errorf("account %q has no users", p.AccountContextParams.Name)
			case 1:
				p.user = entries[0]
			}
		}
	}

	return nil
}

func (p *GenerateConfigParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}
	p.user, err = ctx.StoreCtx().PickUser(p.AccountContextParams.Name)
	if err != nil {
		return err
	}
	return nil
}

func (p *GenerateConfigParams) Load(ctx ActionCtx) error {
	return nil
}

func (p *GenerateConfigParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *GenerateConfigParams) Validate(ctx ActionCtx) error {
	var err error

	if p.AccountContextParams.Name == "" {
		return fmt.Errorf("account is required")
	}
	if p.user == "" {
		return fmt.Errorf("user is required")
	}

	p.entityKP, err = ctx.StoreCtx().KeyStore.GetUserKey(p.AccountContextParams.Name, p.user)
	if err != nil {
		return err
	}

	if !ctx.StoreCtx().Store.Has(store.Accounts, p.AccountContextParams.Name, store.Users, store.JwtName(p.user)) {
		return fmt.Errorf("user %q not found in %q", p.user, p.AccountContextParams.Name)
	}

	p.entityJwt, err = ctx.StoreCtx().Store.Read(store.Accounts, p.AccountContextParams.Name, store.Users, store.JwtName(p.user))
	if err != nil {
		return err
	}

	return nil
}

func (p *GenerateConfigParams) Run(ctx ActionCtx) error {
	if p.entityKP == nil {
		return fmt.Errorf("user was not found - please specify it")
	}

	seed, err := p.entityKP.Seed()
	if err != nil {
		return fmt.Errorf("error getting seed for user %q: %v", p.user, err)
	}

	v := FormatConfig("User", string(p.entityJwt), string(seed))
	return Write(p.out, v)
}
