/*
 * Copyright 2018-2020 The NATS Authors
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

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createClearRevokeUserCmd() *cobra.Command {
	var params ClearRevokeUserParams
	cmd := &cobra.Command{
		Use:          "delete-user",
		Aliases:      []string{"delete_user"},
		Short:        "Remove a user revocation",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().StringVarP(&params.user, "name", "n", "", "user name")
	params.userKey.BindFlags("user-public-key", "u", nkeys.PrefixByteUser, cmd)
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	revokeCmd.AddCommand(createClearRevokeUserCmd())
}

// ClearRevokeUserParams hold the info necessary to add a user to the revocation list in an account
type ClearRevokeUserParams struct {
	AccountContextParams
	user    string
	userKey PubKeyParams
	claim   *jwt.AccountClaims
	SignerParams
}

func (p *ClearRevokeUserParams) SetDefaults(ctx ActionCtx) error {
	if p.userKey.publicKey != "" && p.user != "" {
		return fmt.Errorf("user and user-public-key are mutually exclusive")
	}
	p.userKey.AllowWildcard = true
	p.AccountContextParams.SetDefaults(ctx)
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)
	return nil
}

func (p *ClearRevokeUserParams) PreInteractive(ctx ActionCtx) error {
	return p.AccountContextParams.Edit(ctx)
}

func (p *ClearRevokeUserParams) Load(ctx ActionCtx) error {
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

func buildRevokedPublicKeyChoices(accountName string, ctx ActionCtx) ([]PubKeyChoice, error) {
	var choices []PubKeyChoice
	st := ctx.StoreCtx().Store
	accClaim, err := st.ReadAccountClaim(accountName)
	if err != nil || len(accClaim.Revocations) == 0 {
		return choices, err
	}

	keyToName := map[string]string{}
	keyToName[jwt.All] = "All Users"
	infos, err := ListUsers(ctx.StoreCtx().Store, accountName)
	if err != nil {
		return nil, err
	}
	for _, i := range infos {
		if i.Err == nil {
			keyToName[i.Claims.Claims().Subject] = i.Name
		}
	}

	for key := range accClaim.Revocations {
		pkc := PubKeyChoice{}
		pkc.Key = key
		n := keyToName[key]
		if n == "" {
			n = "[Unknown User]"
		}
		pkc.Label = fmt.Sprintf("%s: %s", key, n)
		choices = append(choices, pkc)
	}
	return choices, nil
}

func (p *ClearRevokeUserParams) PostInteractive(ctx ActionCtx) error {
	choices, err := buildRevokedPublicKeyChoices(p.AccountContextParams.Name, ctx)
	if err != nil || len(choices) == 0 {
		return err
	}
	if err := p.userKey.Select("select revoked user to clear", choices...); err != nil {
		return err
	}
	return p.SignerParams.Edit(ctx)
}

func (p *ClearRevokeUserParams) Validate(ctx ActionCtx) error {
	if len(p.claim.Revocations) == 0 {
		return fmt.Errorf("no user revocations set in account %s", p.AccountContextParams.Name)
	}
	if p.userKey.publicKey == "" && p.user == "" {
		return fmt.Errorf("user or user-public-key is required")
	}
	if err := p.userKey.Valid(); err != nil {
		return err
	}
	return p.SignerParams.Resolve(ctx)
}

func (p *ClearRevokeUserParams) Run(ctx ActionCtx) (store.Status, error) {
	// we test for the explicit entry - as checking for revocations
	_, ok := p.claim.Revocations[p.userKey.publicKey]
	if !ok {
		return nil, fmt.Errorf("revocation for user %q was not found", p.userKey.publicKey)
	}

	p.claim.ClearRevocation(p.userKey.publicKey)
	token, err := p.claim.Encode(p.signerKP)
	if err != nil {
		return nil, err
	}
	r := store.NewDetailedReport(true)
	StoreAccountAndUpdateStatus(ctx, token, r)
	if r.HasNoErrors() {
		if p.userKey.publicKey == jwt.All {
			r.AddOK("deleted all user revocation")
		} else {
			r.AddOK("deleted user revocation for %q", p.userKey.publicKey)
		}
	}
	return r, nil
}
