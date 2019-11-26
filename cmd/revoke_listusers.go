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
	"time"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
	"github.com/xlab/tablewriter"
)

func createRevokeListUsersCmd() *cobra.Command {
	var params RevokeListUserParams
	cmd := &cobra.Command{
		Use:          "list_users",
		Short:        "List users revoked in an account",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}
			return nil
		},
	}
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	revokeCmd.AddCommand(createRevokeListUsersCmd())
}

// RevokeListUserParams hold the info necessary to add a user to the revocation list in an account
type RevokeListUserParams struct {
	AccountContextParams
	claim *jwt.AccountClaims
}

func (p *RevokeListUserParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.SetDefaults(ctx)
	return nil
}

func (p *RevokeListUserParams) PreInteractive(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}
	return nil
}

func (p *RevokeListUserParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	p.claim, err = ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		return err
	}

	return nil
}

func (p *RevokeListUserParams) Validate(ctx ActionCtx) error {
	return nil
}

func (p *RevokeListUserParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *RevokeListUserParams) Run(ctx ActionCtx) (store.Status, error) {
	table := tablewriter.CreateTable()
	table.UTF8Box()

	name := p.claim.Name

	if name == "" {
		name = p.claim.Subject
	}

	table.AddTitle(fmt.Sprintf("Revoked Users for %s", name))
	table.AddHeaders("Public Key", "Revoke Credentials Before")

	for pubKey, at := range p.claim.Revocations {
		t := time.Unix(at, 0)
		formatted := t.Format(time.RFC1123)
		table.AddRow(pubKey, formatted)
	}

	return nil, Write("--", []byte(table.Render()))
}
