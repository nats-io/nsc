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
	"strings"
	"time"

	cli "github.com/nats-io/cliprompts/v2"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createClearRevokeUserCmd() *cobra.Command {
	var params ClearRevokeUserParams
	cmd := &cobra.Command{
		Use:          "delete_user",
		Aliases:      []string{"delete-user"},
		Short:        "Remove a user revocation",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}

			if !QuietMode() {
				cmd.Printf("Cleared revocation of user %s with public key %s\n", params.user, params.userPubKey)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.user, "name", "n", "", "user name")
	cmd.Flags().StringVarP(&params.userPubKey, "user-public-key", "u", "", "public user key (use when user was generated outside of nsc)")
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	revokeCmd.AddCommand(createClearRevokeUserCmd())
}

// ClearRevokeUserParams hold the info necessary to add a user to the revocation list in an account
type ClearRevokeUserParams struct {
	AccountContextParams
	user       string
	userPubKey string
	claim      *jwt.AccountClaims
	SignerParams
}

func (p *ClearRevokeUserParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.SetDefaults(ctx)
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)
	return nil
}

func (p *ClearRevokeUserParams) PreInteractive(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}

	st := ctx.StoreCtx().Store
	accClaim, err := st.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil || len(accClaim.Revocations) == 0 {
		return err
	}
	keyToUserName := map[string]string{}
	users, err := st.ListEntries(store.Accounts, p.AccountContextParams.Name, store.Users)
	if err != nil {
		return err
	}
	for _, user := range users {
		if uc, err := st.ReadUserClaim(p.AccountContextParams.Name, user); err == nil {
			if _, ok := accClaim.Revocations[uc.Subject]; ok {
				keyToUserName[uc.Subject] = uc.Name
			}
		}
	}

	choices := make([]string, 1, len(accClaim.Revocations)+1)
	choices[0] = "none"
	for userNkey := range accClaim.Revocations {
		choice := ""
		if name, ok := keyToUserName[userNkey]; ok {
			choice = fmt.Sprintf("%s: %s", userNkey, name)
		} else {
			choice = userNkey
		}
		choices = append(choices, choice)
	}
	if choice, err := cli.Select("Revoked users to remove", "", choices); err != nil {
		return err
	} else if choice == 0 {
		return fmt.Errorf("no Nkey selected")
	} else {
		p.userPubKey = strings.Split(choices[choice], ":")[0]
	}
	if err := p.SignerParams.Edit(ctx); err != nil {
		return err
	}
	return nil
}

func (p *ClearRevokeUserParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	if p.user == "" && p.userPubKey == "" {
		n := ctx.StoreCtx().DefaultUser(p.AccountContextParams.Name)
		if n != nil {
			p.user = *n
		}
	}
	if p.userPubKey == "" && p.user == "" {
		return fmt.Errorf("user or user-public-key are required")
	}
	if p.userPubKey != "" && p.user != "" {
		return fmt.Errorf("user and user-public-key are mutually exclusive")
	}

	p.claim, err = ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		return err
	}

	if p.userPubKey != "" {
		return nil
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

func (p *ClearRevokeUserParams) Validate(ctx ActionCtx) error {
	if !nkeys.IsValidPublicUserKey(p.userPubKey) {
		return fmt.Errorf("user-public-key %q is not a valid public user nkey", p.userPubKey)
	}
	if err := p.SignerParams.Resolve(ctx); err != nil {
		return err
	}

	return nil
}

func (p *ClearRevokeUserParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *ClearRevokeUserParams) Run(ctx ActionCtx) (store.Status, error) {
	if !p.claim.IsRevokedAt(p.userPubKey, time.Unix(0, 0)) {
		return nil, fmt.Errorf("user with public key %s is not revoked", p.userPubKey)
	}

	p.claim.ClearRevocation(p.userPubKey)
	token, err := p.claim.Encode(p.signerKP)
	if err != nil {
		return nil, err
	}
	r := store.NewDetailedReport(true)
	StoreAccountAndUpdateStatus(ctx, token, r)
	if r.HasNoErrors() {
		r.AddOK("cleared user revocation for account %s", p.userPubKey)
	}
	return r, nil
}
