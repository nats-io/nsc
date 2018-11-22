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
		SilenceUsage: true,
		Example:      `nsc generate config --account actname --user uname`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().StringVarP(&params.name, "name", "n", "", "name of the entity")
	cmd.Flags().StringVarP(&params.out, "output-file", "o", "", "output file '--' is stdout")
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	generateCmd.AddCommand(createGenerateConfigCmd())
}

type GenerateConfigParams struct {
	AccountContextParams
	kind      string
	name      string
	out       string
	account   bool
	user      bool
	entityKP  nkeys.KeyPair
	entityJwt []byte
}

func (p *GenerateConfigParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.SetDefaults(ctx)
	return nil
}

func (p *GenerateConfigParams) PreInteractive(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}
	if p.name == "" {
		p.name, err = ctx.StoreCtx().PickUser(p.AccountContextParams.Name)
		if err != nil {
			return err
		}
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
	if p.name == "" {
		return fmt.Errorf("name is required")
	}

	p.entityKP, err = ctx.StoreCtx().KeyStore.GetUserKey(p.AccountContextParams.Name, p.name)
	if err != nil {
		return err
	}

	if !ctx.StoreCtx().Store.Has(store.Accounts, p.AccountContextParams.Name, store.Users, store.JwtName(p.name)) {
		return fmt.Errorf("user %q not found", p.name)
	}

	p.entityJwt, err = ctx.StoreCtx().Store.Read(store.Accounts, p.AccountContextParams.Name, store.Users, store.JwtName(p.name))
	if err != nil {
		return err
	}

	return nil
}

func (p *GenerateConfigParams) Run(ctx ActionCtx) error {
	seed, err := p.entityKP.Seed()
	if err != nil {
		return fmt.Errorf("error getting seed for user %q: %v", p.name, err)
	}

	v := FormatConfig("User", string(p.entityJwt), string(seed))
	fmt.Println(string(v))

	return nil
}
