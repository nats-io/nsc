/*
 * Copyright 2018-2022 The NATS Authors
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
	"strings"
	"time"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createRevokeUserCmd() *cobra.Command {
	var params RevokeUserParams
	cmd := &cobra.Command{
		Use:          "add-user",
		Aliases:      []string{"add_user"},
		Short:        "Revoke a user",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().StringVarP(&params.user, "name", "n", "", "user name")
	cmd.Flags().VarP(&params.at, "at", "", "revokes all user credentials created"+
		" or edited before a Unix timestamp ('0' is treated as now, accepted formats are RFC3339 or #seconds since epoch)")
	params.userKey.BindFlags("user-public-key", "u", nkeys.PrefixByteUser, cmd)
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	revokeCmd.AddCommand(createRevokeUserCmd())
}

// RevokeUserParams hold the info necessary to add a user to the revocation list in an account
type RevokeUserParams struct {
	AccountContextParams
	at      dateTime
	user    string
	userKey PubKeyParams
	claim   *jwt.AccountClaims
	SignerParams
}

func (p *RevokeUserParams) SetDefaults(ctx ActionCtx) error {
	if p.userKey.publicKey != "" && p.user != "" {
		return fmt.Errorf("user and user-public-key are mutually exclusive")
	}
	p.userKey.AllowWildcard = true
	p.AccountContextParams.SetDefaults(ctx)
	if err := p.userKey.SetDefaults(ctx); err != nil {
		return err
	}
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)
	return nil
}

func (p *RevokeUserParams) PreInteractive(ctx ActionCtx) error {
	return p.AccountContextParams.Edit(ctx)
}

func (p *RevokeUserParams) Load(ctx ActionCtx) error {
	var err error
	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	if p.user != "" {
		entries, err := ListUsers(ctx.StoreCtx().Store, p.AccountContextParams.Name)
		if err != nil {
			return err
		}

		n := strings.ToLower(p.user)
		for _, e := range entries {
			if e.Err == nil && strings.ToLower(e.Name) == n {
				p.userKey.publicKey = e.Claims.Claims().Subject
				break
			}
		}
		if p.userKey.publicKey == "" {
			return fmt.Errorf("user %q not found", p.user)
		}
	} else if p.user == "" && p.userKey.publicKey == "" && !InteractiveFlag {
		uc, err := ctx.StoreCtx().DefaultUserClaim(p.AccountContextParams.Name)
		if err != nil {
			return err
		}
		p.userKey.publicKey = uc.Subject
	}

	p.claim, err = ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
	return err
}

func buildUserPublicKeyChoices(accountName string, ctx ActionCtx) ([]PubKeyChoice, error) {
	var choices []PubKeyChoice
	keyToName := map[string]string{}
	keyToName[jwt.All] = "All Users"
	infos, err := ListUsers(ctx.StoreCtx().Store, accountName)
	if err != nil {
		return nil, err
	}
	for _, i := range infos {
		if i.Err == nil {
			pkc := PubKeyChoice{}
			pkc.Key = i.Claims.Claims().Subject
			pkc.Label = i.Name
			choices = append(choices, pkc)
		}
	}
	return choices, nil
}

func (p *RevokeUserParams) PostInteractive(ctx ActionCtx) error {
	choices, err := buildUserPublicKeyChoices(p.AccountContextParams.Name, ctx)
	byName := false

	if len(choices) > 0 {
		byName, err = cli.Confirm("Revoke a user by name", true)
		if err != nil {
			return err
		}
	}
	if byName {
		if err != nil || len(choices) == 0 {
			return err
		}
		if err := p.userKey.Select("Select revoked user to clear", choices...); err != nil {
			return err
		}
	} else if err := p.userKey.Edit(); err != nil {
		return err
	}

	if p.at == 0 {
		if _, err := cli.Prompt("revoke all credentials created before (0 is now, formats are RFC3339 or #seconds since epoch)",
			fmt.Sprintf("%d", p.at), cli.Val(p.at.Set)); err != nil {
			return err
		}
	}
	if err := p.SignerParams.Edit(ctx); err != nil {
		return err
	}

	return nil
}

func (p *RevokeUserParams) Validate(ctx ActionCtx) error {
	if p.userKey.publicKey == "" && p.user == "" {
		return fmt.Errorf("user or user-public-key is required")
	}
	if err := p.userKey.Valid(); err != nil {
		return err
	}
	return p.SignerParams.Resolve(ctx)
}

func (p *RevokeUserParams) Run(ctx ActionCtx) (store.Status, error) {
	if p.at == 0 {
		p.claim.Revoke(p.userKey.publicKey)
	} else {
		p.claim.RevokeAt(p.userKey.publicKey, time.Unix(int64(p.at), 0))
	}
	token, err := p.claim.Encode(p.signerKP)
	if err != nil {
		return nil, err
	}
	r := store.NewDetailedReport(true)
	StoreAccountAndUpdateStatus(ctx, token, r)
	if r.HasNoErrors() {
		if p.userKey.publicKey == jwt.All {
			when := int64(p.at)
			if when == 0 {
				when = time.Now().Unix()
			}
			r.AddOK("revoked all users issued before %s", time.Unix(when, 0).String())
		} else {
			r.AddOK("revoked user %q", p.userKey.publicKey)
		}
	}
	return r, nil
}
