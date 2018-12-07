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

	"github.com/spf13/cobra"
)

type AccountContextParams struct {
	Name string
}

func (p *AccountContextParams) BindFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&p.Name, "account", "a", "", "account name")
}

func (p *AccountContextParams) SetDefaults(ctx ActionCtx) error {
	config := GetConfig()
	if p.Name != "" {
		err := config.SetAccountTemp(p.Name)
		if err != nil {
			return err
		}
		ctx.StoreCtx().Account.Name = p.Name
		return nil
	} else {
		if config.Account != "" {
			ctx.StoreCtx().Account.Name = config.Account
			p.Name = config.Account
		}
	}
	return nil
}

func (p *AccountContextParams) Edit(ctx ActionCtx) error {
	var err error
	p.Name, err = ctx.StoreCtx().PickAccount(p.Name)
	if err != nil {
		return err
	}
	ctx.StoreCtx().Account.Name = p.Name
	return nil
}

func (p *AccountContextParams) Validate(ctx ActionCtx) error {
	// default account was not found by get context, so we either we have none or many
	if p.Name == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return errors.New("an account is required")
	}
	return nil
}
