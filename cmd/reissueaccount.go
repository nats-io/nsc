/*
 * Copyright 2020-2023 The NATS Authors
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

	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
)

func createReissueAccountCmd() *cobra.Command {
	var params reissueAccount
	cmd := &cobra.Command{
		Use:          "account",
		Short:        "Re-issues all accounts with a new identity and re-signs affected users",
		Example:      `nsc reissue account`,
		Args:         MaxArgs(0),
		SilenceUsage: false,
		Hidden:       true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunMaybeStorelessAction(cmd, args, &params); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&params.turnIntoSigningKey, "convert-to-signing-key", "", false,
		"turn account identity key into signing key (avoids user re-signing)")
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

type reissueAccount struct {
	AccountContextParams
	turnIntoSigningKey bool
	name               string
}

func (p *reissueAccount) SetDefaults(ctx ActionCtx) error {
	return p.AccountContextParams.SetDefaults(ctx)
}

func (p *reissueAccount) PreInteractive(ctx ActionCtx) error {
	return nil
}

func (p *reissueAccount) Load(ctx ActionCtx) error {
	return nil
}

func (p *reissueAccount) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *reissueAccount) Validate(ctx ActionCtx) error {
	store := ctx.StoreCtx().Store
	if store.IsManaged() {
		return fmt.Errorf("resign is only supported in non managed stores")
	}
	return nil
}

func (p *reissueAccount) Run(ctx ActionCtx) (store.Status, error) {
	var err error
	r := store.NewDetailedReport(true)
	s := ctx.StoreCtx().Store
	ks := ctx.StoreCtx().KeyStore
	accounts, err := s.ListSubContainers(store.Accounts)

	// maybe filter to the account name provided
	if ctx.CurrentCmd().Flags().Changed("account") {
		var buf []string
		name := ctx.StoreCtx().Account.Name
		for _, n := range accounts {
			if n == name {
				buf = append(buf, n)
			}
		}
		accounts = buf
	}

	if err != nil {
		return nil, err
	}
	for _, n := range accounts {
		rr := store.NewDetailedReport(false)
		r.Add(rr)
		ac, err := s.ReadAccountClaim(n)
		if err != nil {
			rr.AddError("failed to load account %s: %v", n, err)
			return r, err
		}

		akp, err := nkeys.CreateAccount()
		if err != nil {
			rr.AddError("failed to generate new account identity: %v", err)
			return r, err
		}
		if _, err := ks.Store(akp); err != nil {
			rr.AddError("failed to store new account identity: %v", err)
			return r, err
		}
		old := ac.Subject
		ac.Subject, err = akp.PublicKey()
		if p.turnIntoSigningKey {
			ac.SigningKeys.Add(old)
		}
		// if we have access to the existing operator signing key that issued the
		// account we are going to use it to re-sign the account
		pk := ac.Issuer
		sk, err := ks.GetKeyPair(pk)
		if sk == nil {
			err = fmt.Errorf("failed to find key %q", pk)
		}
		if err == nil {
			_, err = sk.PrivateKey()
		}
		if err != nil {
			rr.AddWarning("failed to obtain find key account signer %q", ac.Issuer)
			// if we failed, we are just going to attempt to sign with any operator key
			keys, err := ctx.StoreCtx().GetOperatorKeys()
			if err != nil {
				rr.AddError("failed to read the operator keys: %v", err)
				return r, err
			}
			for _, k := range keys {
				pk = k
				sk, err = ks.GetKeyPair(k)
				if sk == nil {
					err = fmt.Errorf("failed to find key %q", pk)
				}
				if err == nil {
					_, err = sk.PrivateKey()
				}
				if err == nil {
					break
				}
			}
		}
		if sk == nil {
			if err != nil {
				rr.AddError("failed to read load any of the operator keys")
				return r, err
			}
		}

		token, err := ac.Encode(sk)
		if err != nil {
			rr.AddError("failed to sign account with %s: %v", pk, err)
			return r, err
		}

		if err := s.StoreRaw([]byte(token)); err != nil {
			rr.AddError("failed to store updated account: %v", err)
			return r, err
		}

		rr.AddOK("account %q re-was reissued with new identity: %s", ac.Name, ac.Subject)

		users, err := s.ListEntries(store.Accounts, ac.Name, store.Users)
		if err != nil {
			rr.AddError("failed to list users for account %s: %v", ac.Name, err)
			return r, err
		}
		for _, u := range users {
			uc, err := s.ReadUserClaim(ac.Name, u)
			if err != nil {
				rr.AddError("failed to load user %q account %s: %v", u, ac.Name, err)
				return r, err
			}
			issuer := uc.Issuer
			ask, err := ks.GetKeyPair(issuer)
			if ask == nil {
				err = fmt.Errorf("failed to find key %q", pk)
			}
			if err == nil {
				_, err = ask.PrivateKey()
			}
			if err != nil {
				rr.AddWarning("failed to obtain find key account signing key %q", issuer)
				// if we failed, we are just going to attempt to sign with any operator key
				keys, err := ctx.StoreCtx().GetAccountKeys(ac.Name)
				if err != nil {
					r.AddError("failed to read the account keys: %v", err)
					return r, err
				}
				for _, k := range keys {
					issuer = k
					ask, err = ks.GetKeyPair(k)
					if err == nil {
						_, err = ask.PrivateKey()
					}
					if err == nil {
						break
					}
				}
			}
			if ask == nil {
				if err != nil {
					rr.AddError("failed to read load any of the operator keys")
					return r, err
				}
			}
			uc.IssuerAccount = ""
			if issuer != ac.Subject {
				uc.IssuerAccount = ac.Subject
			}
			ut, err := uc.Encode(ask)
			if err != nil {
				rr.AddError("failed to sign user %q on account %s with %s: %v", u, ac.Name, issuer, err)
				return r, err
			}
			if err := s.StoreRaw([]byte(ut)); err != nil {
				rr.AddError("failed to store updated user: %v", err)
				return r, err
			}

			rr.AddOK("user %q re-was reissued", uc.Name)
		}

	}
	return r, nil
}
