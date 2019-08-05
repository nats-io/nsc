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
	"strconv"
	"time"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
	"github.com/spf13/cobra"
)

func createRevokeUserCmd() *cobra.Command {
	var params RevokeUserParams
	cmd := &cobra.Command{
		Use:          "add_user",
		Short:        "Revoke a user",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}

			if !QuietMode() {
				cmd.Printf("Revoked user %s with public key %s\n", params.user, params.userPubKey)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.user, "name", "n", "", "user name")
	cmd.Flags().IntVarP(&params.at, "at", "", 0, "revokes all user credentials created before a Unix timestamp ('0' is treated as now)")

	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	revokeCmd.AddCommand(createRevokeUserCmd())
}

// RevokeUserParams hold the info necessary to add a user to the revocation list in an account
type RevokeUserParams struct {
	AccountContextParams
	at         int
	user       string
	userPubKey string
	claim      *jwt.AccountClaims
	SignerParams
}

func (p *RevokeUserParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.SetDefaults(ctx)
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)
	return nil
}

func (p *RevokeUserParams) canParse(s string) error {
	_, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("%s is invalid: %v", s, err)
	}
	return nil
}

func (p *RevokeUserParams) PreInteractive(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}
	if p.user == "" {
		p.user, err = ctx.StoreCtx().PickUser(p.AccountContextParams.Name)
		if err != nil {
			return err
		}
	}
	if p.at == 0 {
		at := fmt.Sprintf("%d", p.at)
		at, err = cli.Prompt("revoke all credentials created before (0 is now)", at, true, p.canParse)
		p.at, err = strconv.Atoi(at)
	}
	if err := p.SignerParams.Edit(ctx); err != nil {
		return err
	}
	return nil
}

func (p *RevokeUserParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	if p.user == "" {
		n := ctx.StoreCtx().DefaultUser(p.AccountContextParams.Name)
		if n != nil {
			p.user = *n
		}
	}

	if p.user == "" {
		return fmt.Errorf("user is required")
	}

	p.claim, err = ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		return err
	}

	userClaim, err := ctx.StoreCtx().Store.ReadUserClaim(p.AccountContextParams.Name, p.user)
	if err != nil {
		return err
	}

	if err != nil || userClaim == nil {
		return fmt.Errorf("user is required")
	}

	p.userPubKey = userClaim.Subject

	return nil
}

func (p *RevokeUserParams) Validate(ctx ActionCtx) error {

	if err := p.SignerParams.Resolve(ctx); err != nil {
		return err
	}

	return nil
}

func (p *RevokeUserParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *RevokeUserParams) Run(ctx ActionCtx) error {

	if p.at == 0 {
		p.claim.Revoke(p.userPubKey)
	} else {
		p.claim.RevokeAt(p.userPubKey, time.Unix(int64(p.at), 0))
	}

	token, err := p.claim.Encode(p.signerKP)
	if err != nil {
		return err
	}
	return ctx.StoreCtx().Store.StoreClaim([]byte(token))
}
