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

func createGenerateCredsCmd() *cobra.Command {
	var params GenerateCredsParams
	cmd := &cobra.Command{
		Use:          "creds",
		Short:        "Generate a credentials file for an user",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		Example:      `nsc generate creds --account a --name u`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}
			if !QuietMode() && params.out != "--" {
				cmd.Printf("Success!! - generated %#q\n", params.out)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.user, "name", "n", "", "user name")
	cmd.Flags().StringVarP(&params.out, "output-file", "o", "--", "output file '--' is stdout")
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	generateCmd.AddCommand(createGenerateCredsCmd())
}

type GenerateCredsParams struct {
	AccountContextParams
	user      string
	out       string
	entityKP  nkeys.KeyPair
	entityJwt []byte
}

func (p *GenerateCredsParams) SetDefaults(ctx ActionCtx) error {
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

func (p *GenerateCredsParams) PreInteractive(ctx ActionCtx) error {
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

func (p *GenerateCredsParams) Load(ctx ActionCtx) error {
	return nil
}

func (p *GenerateCredsParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *GenerateCredsParams) Validate(ctx ActionCtx) error {
	var err error

	if p.AccountContextParams.Name == "" {
		return fmt.Errorf("account is required")
	}
	if p.user == "" {
		return fmt.Errorf("user is required")
	}

	if !ctx.StoreCtx().Store.Has(store.Accounts, p.AccountContextParams.Name, store.Users, store.JwtName(p.user)) {
		return fmt.Errorf("user %q not found in %q", p.user, p.AccountContextParams.Name)
	}

	p.entityJwt, err = ctx.StoreCtx().Store.Read(store.Accounts, p.AccountContextParams.Name, store.Users, store.JwtName(p.user))
	if err != nil {
		return err
	}

	uc, err := jwt.DecodeUserClaims(string(p.entityJwt))
	if err != nil {
		return fmt.Errorf("error decoding user %q in %q jwt: %v", p.AccountContextParams.Name, p.user, err)
	}

	p.entityKP, err = ctx.StoreCtx().KeyStore.GetKeyPair(uc.Subject)
	if err != nil {
		return err
	}

	if p.entityKP == nil {
		return fmt.Errorf("user was not found - please specify it")
	}

	return nil
}

func (p *GenerateCredsParams) Run(ctx ActionCtx) (store.Status, error) {
	d, err := GenerateConfig(ctx.StoreCtx().Store, p.AccountContextParams.Name, p.user, p.entityKP)
	if err != nil {
		return nil, err
	}
	if err := Write(p.out, d); err != nil {
		return nil, err
	}
	var s store.Status
	if !IsStdOut(p.out) {
		s = store.OKStatus("wrote credentials to %#q", AbbrevHomePaths(p.out))
	}
	return s, nil
}

func GenerateConfig(s *store.Store, account string, user string, userKey nkeys.KeyPair) ([]byte, error) {
	if s.Has(store.Accounts, account, store.Users, store.JwtName(user)) {
		d, err := s.Read(store.Accounts, account, store.Users, store.JwtName(user))
		if err != nil {
			return nil, err
		}
		if userKey == nil {
			return nil, errors.New("userKey was not provided")
		}
		seed, err := userKey.Seed()
		if err != nil {
			return nil, fmt.Errorf("error getting seed: %v", err)
		}
		return jwt.FormatUserConfig(string(d), seed)
	}
	return nil, fmt.Errorf("unable to find user jwt")
}
