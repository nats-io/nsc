/*
 * Copyright 2019 The NATS Authors
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
	"os"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createDeleteUserCmd() *cobra.Command {
	var params DeleteUserParams
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Delete an user",
		Args:  cobra.MaximumNArgs(1),
		Example: `nsc delete user -n name
nsc delete user -i`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().StringSliceVarP(&params.names, "name", "n", nil, "name of user(s) to delete")
	cmd.Flags().BoolVarP(&params.revoke, "revoke", "R", false, "revoke user before deleting")
	cmd.Flags().BoolVarP(&params.rmNKey, "rm-nkey", "D", false, "delete the user key")
	cmd.Flags().BoolVarP(&params.rmCreds, "rm-creds", "C", false, "delete the user creds")
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	deleteCmd.AddCommand(createDeleteUserCmd())
}

type DeleteUserParams struct {
	AccountContextParams
	SignerParams
	names   []string
	revoke  bool
	rmNKey  bool
	rmCreds bool
}

func (p *DeleteUserParams) SetDefaults(ctx ActionCtx) error {
	if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
		return err
	}
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)

	if len(ctx.Args()) > 0 {
		p.names = append(p.names, ctx.Args()[0])
	}

	return nil
}

func (p *DeleteUserParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}

	users, err := ctx.StoreCtx().Store.ListEntries(store.Accounts, p.AccountContextParams.Name, store.Users)
	if err != nil {
		return err
	}
	if len(users) == 0 {
		return fmt.Errorf("account %q doesn't have any users - add one first", p.AccountContextParams.Name)
	}
	if len(users) > 0 {
		sel, err := cli.MultiSelect("select users", users)
		if err != nil {
			return err
		}
		p.names = nil
		for _, i := range sel {
			p.names = append(p.names, users[i])
		}
	}

	m := "revoke user before deleting"
	if len(p.names) > 1 {
		m = "revoke users before deleting"
	}
	p.revoke, err = cli.Confirm(m, false)
	if err != nil {
		return err
	}

	m = "delete associated nkey"
	if len(p.names) > 1 {
		m = "delete associated nkeys"
	}
	p.rmNKey, err = cli.Confirm(m, false)
	if err != nil {
		return err
	}

	m = "delete associated creds file"
	if len(p.names) > 1 {
		m = "delete associated creds files"
	}
	p.rmCreds, err = cli.Confirm(m, false)
	if err != nil {
		return err
	}

	return nil
}

func (p *DeleteUserParams) Load(ctx ActionCtx) error {
	return nil
}

func (p *DeleteUserParams) PostInteractive(ctx ActionCtx) error {
	var err error

	m := "deleting a user, nkey or creds file cannot be undone - continue"
	if len(p.names) > 1 {
		m = "deleting users, nkeys or creds files cannot be undone - continue"
	}
	ok, err := cli.Confirm(m, false)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("delete cancelled")
	}

	if err := p.SignerParams.Edit(ctx); err != nil {
		return err
	}

	return nil
}

func (p *DeleteUserParams) Validate(ctx ActionCtx) error {
	if len(p.names) == 0 {
		return errors.New("please specify an user to delete")
	}

	s := ctx.StoreCtx().Store
	for _, n := range p.names {
		_, err := s.ReadUserClaim(p.AccountContextParams.Name, n)
		if err != nil {
			return err
		}
	}

	if err := p.SignerParams.Resolve(ctx); err != nil {
		return err
	}

	return nil
}

func (p *DeleteUserParams) Run(ctx ActionCtx) (store.Status, error) {
	r := store.NewReport(store.OK, "delete users")
	revoked := false
	s := ctx.StoreCtx().Store
	ac, err := s.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		r.AddError("error loading account: %v", err)
		return r, err
	}
	for _, n := range p.names {
		// cannot fail
		uc, err := s.ReadUserClaim(p.AccountContextParams.Name, n)
		if err != nil {
			r.AddError("error loading user %s: %v", n, err)
			continue
		}

		ru := store.NewReport(store.OK, fmt.Sprintf("user %s [%s]", n, uc.Subject))
		r.Add(ru)

		if p.revoke {
			if ac.Revocations[uc.Subject] == 0 {
				ac.Revoke(uc.Subject)
				ru.AddOK("revoked user")
				revoked = true
			} else {
				ru.AddOK("user is already revoked")
			}
		}

		if err := s.Delete(store.Accounts, p.AccountContextParams.Name, store.Users, store.JwtName(n)); err != nil {
			ru.AddFromError(err)
		} else {
			ru.AddOK("user deleted")
		}
		if p.rmNKey {
			if ctx.StoreCtx().KeyStore.HasPrivateKey(uc.Subject) {
				if err := ctx.StoreCtx().KeyStore.Remove(uc.Subject); err != nil {
					ru.AddFromError(err)
				} else {
					ru.AddOK("deleted private key")
				}
			} else {
				ru.AddOK("private key is not stored")
			}
		}
		if p.rmCreds {
			fp := ctx.StoreCtx().KeyStore.GetUserCredsPath(p.AccountContextParams.Name, n)
			if _, err := os.Stat(fp); os.IsNotExist(err) {
				ru.AddOK("creds file is not stored")
			} else {
				if err := os.Remove(fp); err != nil {
					ru.AddError("error deleting creds file %s: %v", fp, err)
				} else {
					ru.AddOK("removed creds file")
				}
			}
		}
	}

	if revoked {
		token, err := ac.Encode(p.signerKP)
		if err != nil {
			return nil, err
		}
		StoreAccountAndUpdateStatus(ctx, token, r)
		if ctx.StoreCtx().Store.IsManaged() {
			_, err := ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
			if err != nil {
				r.AddWarning("unable to read account %q: %v", p.AccountContextParams.Name, err)
			}
		}
		r.AddOK("edited account %q", p.AccountContextParams.Name)
	}

	return r, nil
}
