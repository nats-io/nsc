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

import "github.com/spf13/cobra"

type AccountUserContextParams struct {
	AccountContextParams
	UserContextParams
}

func (p *AccountUserContextParams) BindFlags(cmd *cobra.Command) {
	p.AccountContextParams.BindFlags(cmd)
	p.UserContextParams.BindFlags(cmd)
}

func (p *AccountUserContextParams) SetDefaults(ctx ActionCtx) error {
	if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
		return err
	}
	if err := p.UserContextParams.SetDefaults(ctx); err != nil {
		return err
	}
	return nil
}

func (p *AccountUserContextParams) Edit(ctx ActionCtx) error {
	if err := p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}
	if err := p.UserContextParams.Edit(ctx); err != nil {
		return err
	}
	return nil
}

func (p *AccountUserContextParams) Validate(ctx ActionCtx) error {
	if err := p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}
	if err := p.UserContextParams.Validate(ctx); err != nil {
		return err
	}
	return nil
}
