/*
 * Copyright 2020-2025 The NATS Authors
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

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
)

func createReissueAccountCmd() *cobra.Command {
	var params reissueAccount
	cmd := &cobra.Command{
		Use: "account",
		Short: "Re-issues the account with a new identity and re-signs affected users.\n" +
			"\tNote use of this command could create a disruption. Please backup your server\n" +
			"\tand nsc environment prior to use.",
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
	cmd.Flags().BoolVarP(&params.force, "force", "", false,
		"proceed with reissue, warning about items that cannot be updated")
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

type reissueAccount struct {
	AccountContextParams
	force bool
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
	s := ctx.StoreCtx().Store
	if s.IsManaged() {
		return fmt.Errorf("reissue is only supported in non managed stores")
	}
	return nil
}

// resolveOperatorKey finds an operator key we can use to sign accounts
func (p *reissueAccount) resolveOperatorKey(ctx ActionCtx, ks *store.KeyStore, currentIssuer string) (nkeys.KeyPair, error) {
	sk, err := resolvePrivateKey(ks, currentIssuer)
	if err == nil && sk != nil {
		return sk, nil
	}
	keys, err := ctx.StoreCtx().GetOperatorKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to read operator keys: %w", err)
	}
	for _, k := range keys {
		sk, err = resolvePrivateKey(ks, k)
		if err == nil && sk != nil {
			return sk, nil
		}
	}
	return nil, fmt.Errorf("no available operator signing key")
}

// resolvePrivateKey checks if we have the private key for a public key
func resolvePrivateKey(ks *store.KeyStore, pubkey string) (nkeys.KeyPair, error) {
	kp, err := ks.GetKeyPair(pubkey)
	if err != nil {
		return nil, err
	}
	if kp == nil {
		return nil, fmt.Errorf("key %q not found", pubkey)
	}
	if _, err = kp.PrivateKey(); err != nil {
		return nil, err
	}
	return kp, nil
}

// targetAccounts returns the list of accounts to reissue
func (p *reissueAccount) targetAccounts(ctx ActionCtx, s *store.Store) ([]string, error) {
	accounts, err := s.ListSubContainers(store.Accounts)
	if err != nil {
		return nil, err
	}
	if ctx.CurrentCmd().Flags().Changed("account") {
		name := ctx.StoreCtx().Account.Name
		for _, n := range accounts {
			if n == name {
				return []string{name}, nil
			}
		}
		return nil, nil
	}
	return accounts, nil
}

func (p *reissueAccount) preflight(ctx ActionCtx) (store.Status, error) {
	r := store.NewDetailedReport(true)
	s := ctx.StoreCtx().Store
	ks := ctx.StoreCtx().KeyStore

	targets, err := p.targetAccounts(ctx, s)
	if err != nil {
		r.AddError("failed to list accounts: %v", err)
		return r, err
	}

	allAccounts, err := s.ListSubContainers(store.Accounts)
	if err != nil {
		r.AddError("failed to list all accounts: %v", err)
		return r, err
	}

	targetSet := make(map[string]bool)

	for _, name := range targets {
		ac, err := s.ReadAccountClaim(name)
		if err != nil {
			r.AddError("failed to read account %s: %v", name, err)
			return r, err
		}
		targetSet[ac.Subject] = true

		rr := store.NewDetailedReport(false)
		rr.Label = fmt.Sprintf("account %q (%s)", name, ac.Subject)
		r.Add(rr)

		// check operator key
		_, opErr := p.resolveOperatorKey(ctx, &ks, ac.Issuer)
		if opErr != nil {
			rr.AddError("no operator signing key available to re-sign account")
		} else {
			rr.AddOK("operator signing key available")
		}

		// check users
		users, err := s.ListEntries(store.Accounts, name, store.Users)
		if err != nil {
			rr.AddError("failed to list users: %v", err)
			continue
		}
		for _, u := range users {
			uc, err := s.ReadUserClaim(name, u)
			if err != nil {
				rr.AddError("failed to read user %q: %v", u, err)
				continue
			}
			issuer := uc.Issuer
			if issuer == ac.Subject {
				// signed by account identity, new key will handle it
				rr.AddOK("user %q can be re-signed", u)
				continue
			}
			_, err = resolvePrivateKey(&ks, issuer)
			if err == nil {
				rr.AddOK("user %q can be re-signed", u)
			} else {
				rr.AddWarning("user %q cannot be re-signed (missing key %s)", u, issuer)
			}
		}
	}

	// check cross-account imports
	for _, other := range allAccounts {
		oc, err := s.ReadAccountClaim(other)
		if err != nil {
			r.AddWarning("failed to read account %s: %v", other, err)
			continue
		}
		if targetSet[oc.Subject] {
			continue
		}
		for _, imp := range oc.Imports {
			if !targetSet[imp.Account] {
				continue
			}
			if imp.Token != "" {
				act, err := jwt.DecodeActivationClaims(imp.Token)
				if err != nil {
					r.AddWarning("account %q import %q: cannot decode activation token", other, imp.Subject)
					continue
				}
				_, keyErr := resolvePrivateKey(&ks, act.Issuer)
				if keyErr == nil {
					r.AddOK("account %q import %q: activation token can be re-signed", other, imp.Subject)
				} else {
					r.AddWarning("account %q import %q: activation token cannot be re-signed (missing key %s)", other, imp.Subject, act.Issuer)
				}
			} else {
				r.AddOK("account %q import %q: public import will be updated", other, imp.Subject)
			}
		}
	}

	r.AddWarning("re-run with --force to proceed with reissue")
	return r, nil
}

func (p *reissueAccount) Run(ctx ActionCtx) (store.Status, error) {
	if !p.force {
		return p.preflight(ctx)
	}

	r := store.NewDetailedReport(true)
	s := ctx.StoreCtx().Store
	ks := ctx.StoreCtx().KeyStore

	targets, err := p.targetAccounts(ctx, s)
	if err != nil {
		r.AddError("failed to list accounts: %v", err)
		return r, err
	}

	allAccounts, err := s.ListSubContainers(store.Accounts)
	if err != nil {
		r.AddError("failed to list all accounts: %v", err)
		return r, err
	}

	// track old->new subject mappings for cross-account import updates
	subjectMap := make(map[string]string)
	// track new key pairs by old subject
	newKeyPairs := make(map[string]nkeys.KeyPair)

	for _, name := range targets {
		rr := store.NewDetailedReport(false)
		r.Add(rr)

		ac, err := s.ReadAccountClaim(name)
		if err != nil {
			rr.AddError("failed to load account %s: %v", name, err)
			continue
		}

		// resolve operator key
		opKey, err := p.resolveOperatorKey(ctx, &ks, ac.Issuer)
		if err != nil {
			rr.AddWarning("skipping account %q: %v", name, err)
			continue
		}

		// generate new identity
		akp, err := nkeys.CreateAccount()
		if err != nil {
			rr.AddError("failed to generate new account identity: %v", err)
			return r, err
		}
		if _, err := ks.Store(akp); err != nil {
			rr.AddError("failed to store new account identity: %v", err)
			return r, err
		}
		oldSubject := ac.Subject
		newSubject, err := akp.PublicKey()
		if err != nil {
			rr.AddError("failed to get new account public key: %v", err)
			return r, err
		}
		ac.Subject = newSubject
		subjectMap[oldSubject] = newSubject
		newKeyPairs[oldSubject] = akp

		// update imports referencing previously reissued accounts in this batch
		for i, imp := range ac.Imports {
			mappedSubject, ok := subjectMap[imp.Account]
			if !ok {
				continue
			}
			ac.Imports[i].Account = mappedSubject
			if imp.Token != "" {
				act, err := jwt.DecodeActivationClaims(imp.Token)
				if err != nil {
					rr.AddWarning("import %q: cannot decode activation token: %v", imp.Subject, err)
					continue
				}
				var tokenKey nkeys.KeyPair
				if kp, ok := newKeyPairs[act.Issuer]; ok {
					tokenKey = kp
					if act.IssuerAccount != "" {
						act.IssuerAccount = mappedSubject
					}
				} else {
					tokenKey, err = resolvePrivateKey(&ks, act.Issuer)
					if err != nil {
						rr.AddWarning("import %q: cannot re-sign activation token, missing key %s", imp.Subject, act.Issuer)
						continue
					}
					if act.IssuerAccount != "" {
						act.IssuerAccount = mappedSubject
					}
				}
				newToken, err := act.Encode(tokenKey)
				if err != nil {
					rr.AddWarning("import %q: failed to encode activation token: %v", imp.Subject, err)
					continue
				}
				ac.Imports[i].Token = newToken
				rr.AddOK("import %q: activation token re-signed", imp.Subject)
			} else {
				rr.AddOK("import %q: updated account reference", imp.Subject)
			}
		}

		token, err := ac.Encode(opKey)
		if err != nil {
			rr.AddError("failed to sign account %q: %v", name, err)
			return r, err
		}
		if err := s.StoreRaw([]byte(token)); err != nil {
			rr.AddError("failed to store account %q: %v", name, err)
			return r, err
		}
		rr.AddOK("account %q reissued: %s -> %s", name, oldSubject, newSubject)

		// re-sign users
		users, err := s.ListEntries(store.Accounts, name, store.Users)
		if err != nil {
			rr.AddWarning("failed to list users for %q: %v", name, err)
			continue
		}
		for _, u := range users {
			uc, err := s.ReadUserClaim(name, u)
			if err != nil {
				rr.AddWarning("user %q: failed to read: %v", u, err)
				continue
			}

			issuer := uc.Issuer
			var userKey nkeys.KeyPair

			if issuer == oldSubject {
				// signed by old account identity, use new key
				userKey = akp
			} else {
				// signed by a signing key
				userKey, err = resolvePrivateKey(&ks, issuer)
				if err != nil {
					rr.AddWarning("user %q: cannot re-sign, missing key %s", u, issuer)
					continue
				}
			}

			uc.IssuerAccount = ""
			if issuer != oldSubject {
				uc.IssuerAccount = newSubject
			}

			ut, err := uc.Encode(userKey)
			if err != nil {
				rr.AddWarning("user %q: failed to encode: %v", u, err)
				continue
			}
			if err := s.StoreRaw([]byte(ut)); err != nil {
				rr.AddWarning("user %q: failed to store: %v", u, err)
				continue
			}
			rr.AddOK("user %q re-signed", u)
		}
	}

	// update cross-account imports
	if len(subjectMap) > 0 {
		targetSet := make(map[string]bool)
		for oldSub := range subjectMap {
			targetSet[oldSub] = true
		}
		// also mark new subjects so we don't process reissued accounts
		for _, newSub := range subjectMap {
			targetSet[newSub] = true
		}

		for _, name := range allAccounts {
			ac, err := s.ReadAccountClaim(name)
			if err != nil {
				r.AddWarning("failed to read account %s for import update: %v", name, err)
				continue
			}
			// skip accounts that were reissued
			if targetSet[ac.Subject] {
				continue
			}

			modified := false
			for i, imp := range ac.Imports {
				newSubject, ok := subjectMap[imp.Account]
				if !ok {
					continue
				}
				ac.Imports[i].Account = newSubject
				modified = true

				if imp.Token != "" {
					act, err := jwt.DecodeActivationClaims(imp.Token)
					if err != nil {
						r.AddWarning("account %q import %q: cannot decode activation token: %v", name, imp.Subject, err)
						continue
					}
					// if the token was signed by a reissued account identity, use the new key
					var tokenKey nkeys.KeyPair
					if kp, ok := newKeyPairs[act.Issuer]; ok {
						tokenKey = kp
						if act.IssuerAccount != "" {
							act.IssuerAccount = newSubject
						}
					} else {
						tokenKey, err = resolvePrivateKey(&ks, act.Issuer)
						if err != nil {
							r.AddWarning("account %q import %q: cannot re-sign activation token, missing key %s", name, imp.Subject, act.Issuer)
							continue
						}
						if act.IssuerAccount != "" {
							act.IssuerAccount = newSubject
						}
					}
					newToken, err := act.Encode(tokenKey)
					if err != nil {
						r.AddWarning("account %q import %q: failed to encode activation token: %v", name, imp.Subject, err)
						continue
					}
					ac.Imports[i].Token = newToken
					r.AddOK("account %q import %q: activation token re-signed", name, imp.Subject)
				} else {
					r.AddOK("account %q import %q: updated account reference", name, imp.Subject)
				}
			}

			if modified {
				opKey, err := p.resolveOperatorKey(ctx, &ks, ac.Issuer)
				if err != nil {
					r.AddWarning("account %q: cannot re-sign after import update, no operator key", name)
					continue
				}
				token, err := ac.Encode(opKey)
				if err != nil {
					r.AddWarning("account %q: failed to encode after import update: %v", name, err)
					continue
				}
				if err := s.StoreRaw([]byte(token)); err != nil {
					r.AddWarning("account %q: failed to store after import update: %v", name, err)
					continue
				}
			}
		}
	}

	return r, nil
}
