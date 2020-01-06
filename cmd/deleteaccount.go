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
	"time"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createDeleteAccountCmd() *cobra.Command {
	var params DeleteAccountParams
	cmd := &cobra.Command{
		Use:   "account",
		Short: "Delete an account and associated users",
		Args:  cobra.MaximumNArgs(1),
		Example: `nsc delete account -n name
nsc delete account -i
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}

	cmd.Flags().StringVarP(&params.AccountContextParams.Name, "name", "n", "", "name of account to delete")
	cmd.Flags().BoolVarP(&params.revoke, "revoke", "R", true, "revoke users before deleting")
	cmd.Flags().BoolVarP(&params.rmNkeys, "rm-nkey", "D", false, "delete user keys")
	cmd.Flags().BoolVarP(&params.rmCreds, "rm-creds", "C", false, "delete users creds")
	cmd.Flags().BoolVarP(&params.force, "force", "F", false, "managed accounts must supply --force")

	return cmd
}

func init() {
	deleteCmd.AddCommand(createDeleteAccountCmd())
}

type DeleteAccountParams struct {
	AccountContextParams
	SignerParams
	ac      *jwt.AccountClaims
	force   bool
	revoke  bool
	rmCreds bool
	rmNkeys bool
	users   []string
}

func (p *DeleteAccountParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.Name = NameFlagOrArgument(p.AccountContextParams.Name, ctx)
	if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
		return err
	}
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)

	return nil
}

func (p *DeleteAccountParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}
	p.revoke, err = cli.Confirm("revoke all account users before deleting", true)
	if err != nil {
		return err
	}
	p.rmNkeys, err = cli.Confirm("delete associated account and user nkeys", false)
	if err != nil {
		return err
	}
	p.rmCreds, err = cli.Confirm("delete associated user creds files", false)
	if err != nil {
		return err
	}
	return nil
}

func (p *DeleteAccountParams) Load(ctx ActionCtx) error {
	var err error
	s := ctx.StoreCtx().Store
	p.ac, err = s.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		return err
	}

	p.users, err = s.ListEntries(store.Accounts, p.AccountContextParams.Name, store.Users)
	if err != nil {
		return err
	}

	return nil
}

func (p *DeleteAccountParams) PostInteractive(ctx ActionCtx) error {
	if ctx.StoreCtx().Store.IsManaged() {
		m := "managed accounts may require the account JWT or nkeys to cancel a service - continue"
		ok, err := cli.Confirm(m, false)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("delete cancelled")
		}
	}

	m := "deleting account or account nkey files cannot be undone - continue"
	if len(p.users) > 0 {
		m = "deleting accounts, users, nkeys or creds files cannot be undone - continue"
	}
	ok, err := cli.Confirm(m, false)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("delete cancelled")
	}
	return nil
}

func (p *DeleteAccountParams) Validate(ctx ActionCtx) error {
	if ctx.StoreCtx().Store.IsManaged() && !p.force {
		return errors.New("managed accounts may require the account JWT or nkeys to cancel a service, specify the --force to override")
	}

	if err := p.SignerParams.Resolve(ctx); err != nil {
		return err
	}
	return nil
}

func (p *DeleteAccountParams) Run(ctx ActionCtx) (store.Status, error) {
	ctx.CurrentCmd().SilenceUsage = true

	r := store.NewReport(store.OK, "delete account")
	r.Opt = store.DetailsOnly
	s := ctx.StoreCtx().Store
	for _, n := range p.users {
		uc, err := s.ReadUserClaim(p.AccountContextParams.Name, n)
		if err != nil {
			r.AddError("error loading user %s: %v", n, err)
			continue
		}

		ru := store.NewReport(store.OK, fmt.Sprintf("user %s [%s]", n, uc.Subject))
		r.Add(ru)
		if p.revoke {
			if p.ac.Revocations[uc.Subject] == 0 {
				p.ac.Revoke(uc.Subject)
				ru.AddOK("revoked user")
			} else {
				ru.AddOK("user is already revoked")
			}
		}
		if err := s.Delete(store.Accounts, p.AccountContextParams.Name, store.Users, store.JwtName(n)); err != nil {
			ru.AddFromError(err)
		} else {
			ru.AddOK("user deleted")
		}

		if p.rmNkeys {
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

	// maybe remove the users dir
	_ = s.Delete(store.Accounts, p.AccountContextParams.Name, store.Users)

	// we cannot currently remove the account JWT from the system, but we can expire it
	p.ac.Expires = time.Now().Add(time.Minute).Unix()
	token, err := p.ac.Encode(p.signerKP)
	if err != nil {
		r.AddError("error encoding account jwt: %v", err)
		return r, err
	}
	StoreAccountAndUpdateStatus(ctx, token, r)
	if ctx.StoreCtx().Store.IsManaged() {
		_, err := ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
		if err != nil {
			r.AddWarning("unable to read account %q: %v", p.AccountContextParams.Name, err)
		}
	}
	r.AddOK("expired account %q", p.AccountContextParams.Name)

	if p.rmNkeys {
		// delete the account nkeys
		for _, sk := range p.ac.SigningKeys {
			if ctx.StoreCtx().KeyStore.HasPrivateKey(sk) {
				if err := ctx.StoreCtx().KeyStore.Remove(sk); err != nil {
					r.AddFromError(err)
				} else {
					r.AddOK("deleted signing key %q", sk)
				}
			} else {
				r.AddOK("signing key %q is not stored", sk)
			}
		}
		if ctx.StoreCtx().KeyStore.HasPrivateKey(p.ac.Subject) {
			if err := ctx.StoreCtx().KeyStore.Remove(p.ac.Subject); err != nil {
				r.AddFromError(err)
			} else {
				r.AddOK("deleted privated key %q", p.ac.Subject)
			}
		} else {
			r.AddOK("private key %q is not stored", p.ac.Subject)
		}
	}

	// delete the jwt
	if err := s.Delete(store.Accounts, p.AccountContextParams.Name, store.JwtName(p.AccountContextParams.Name)); err != nil {
		r.AddFromError(err)
	} else {
		r.AddOK("deleted account")
	}

	if err := s.Delete(store.Accounts, p.AccountContextParams.Name); err != nil {
		r.AddFromError(err)
	} else {
		r.AddOK("deleted account directory")
	}

	return r, nil
}
