/*
 * Copyright 2018-2019 The NATS Authors
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

	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

type UserContextParams struct {
	Name string
}

func (p *UserContextParams) BindFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&p.Name, "user", "u", "", "user name")
}

func (p *UserContextParams) SetDefaults(ctx ActionCtx) error {
	config := GetConfig()
	if config.Operator == "" {
		return fmt.Errorf("no operator set - `%s env --operator <name>`", GetToolName())
	}
	if config.Account == "" {
		return fmt.Errorf("no account set - `%s env --account <name>`", GetToolName())
	}
	if p.Name == "" {
		s, err := config.LoadStore(config.Operator)
		if err != nil {
			return err
		}
		names, err := s.ListEntries(store.Accounts, config.Account, store.Users)
		if err != nil {
			return err
		}
		if len(names) == 1 {
			p.Name = names[0]
		}
	}

	return nil
}

func (p *UserContextParams) Edit(ctx ActionCtx) error {
	config := GetConfig()
	var err error
	p.Name, err = ctx.StoreCtx().PickUser(config.Account)
	if err != nil {
		return err
	}
	return nil
}

func (p *UserContextParams) Validate(ctx ActionCtx) error {
	// default account was not found by get context, so we either we have none or many
	if p.Name == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return errors.New("a user is required")
	}
	return nil
}
