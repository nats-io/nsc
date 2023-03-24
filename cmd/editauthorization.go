/*
 * Copyright 2018-2023 The NATS Authors
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

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
)

type EditAccountCalloutParams struct {
	AccountContextParams
	SignerParams
	disable           bool
	AuthUsers         []string
	AllowedAccounts   []string
	RmAuthUsers       []string
	RmAllowedAccounts []string
	XKey              SigningKeysParams
	RmXKey            bool
	claim             *jwt.AccountClaims
}

func createEditAuthorizationCallout() *cobra.Command {
	params := &EditAccountCalloutParams{}
	cmd := &cobra.Command{
		Use:          "authcallout",
		Short:        "Edit an account authorization callout",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, params)
		},
	}

	cmd.Flags().BoolVarP(&params.disable, "disable", "", false, "disable external authorization")
	cmd.Flags().StringSliceVarP(&params.AuthUsers, "auth-user", "", nil, "adds a user public key that bypasses the authorization callout and is used by the authorization service itself")
	cmd.Flags().StringSliceVarP(&params.AllowedAccounts, "allowed-account", "", nil, "adds an account public key that the authorization service can bind authorized users to (specify '*' to allow any account that the service can generate users for)")

	cmd.Flags().StringSliceVarP(&params.RmAuthUsers, "rm-auth-user", "", nil, "removes a user public key that bypasses the authorization callout and is used by the authorization service itself")
	cmd.Flags().StringSliceVarP(&params.RmAllowedAccounts, "rm-allowed-account", "", nil, "removes an account public key or the '*' wildcard that the authorization service can bind authorized users to")
	cmd.Flags().BoolVarP(&params.RmXKey, "rm-curve", "", false, "remove curve encryption target")
	params.XKey.BindFlags("curve", "x", nkeys.PrefixByteCurve, cmd)
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	editCmd.AddCommand(createEditAuthorizationCallout())
}

func (p *EditAccountCalloutParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.Name = NameFlagOrArgument(p.AccountContextParams.Name, ctx)
	if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
		return err
	}

	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)

	if ctx.NothingToDo("auth-user", "rm-auth-user", "allowed-account",
		"rm-allowed-account", "disable", "curve", "rm-curve") {
		return errors.New("please specify some options")
	}

	// fail if are given disable and other flags
	if p.disable && ctx.AnySet("auth-user", "rm-auth-user", "allowed-account",
		"rm-allowed-account", "curve", "rm-curve") {
		return errors.New("--disable is exclusive of all other options")
	}

	return nil
}

func (p *EditAccountCalloutParams) PreInteractive(_ ActionCtx) error {
	return nil
}

func (p *EditAccountCalloutParams) Load(ctx ActionCtx) error {
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

func (p *EditAccountCalloutParams) PostInteractive(_ ActionCtx) error {
	return nil
}

// toPublicKey resolves the public and checks the key for proper type
func toPublicKey(s string, kind nkeys.PrefixByte) (string, error) {
	if s == jwt.AnyAccount {
		return s, nil
	}
	kp, err := store.ResolveKey(s)
	if err != nil {
		return "", err
	}
	if kp == nil {
		return "", fmt.Errorf("%q is not a valid %s key", s, kind)
	}
	if err := nkeys.CompatibleKeyPair(kp, kind); err != nil {
		return "", fmt.Errorf("%q is not a valid %s key", s, kind)
	}
	return kp.PublicKey()
}

func (p *EditAccountCalloutParams) Validate(ctx ActionCtx) error {
	var err error

	if err := p.SignerParams.ResolveWithPriority(ctx, p.claim.Issuer); err != nil {
		return err
	}

	if p.disable {
		return nil
	}

	if ctx.AnySet("curve") {
		if err := p.XKey.Valid(); err != nil {
			return err
		}
	}

	for idx, k := range p.AuthUsers {
		p.AuthUsers[idx], err = toPublicKey(k, nkeys.PrefixByteUser)
		if err != nil {
			return err
		}
	}

	for idx, k := range p.RmAuthUsers {
		p.RmAuthUsers[idx], err = toPublicKey(k, nkeys.PrefixByteUser)
		if err != nil {
			return err
		}
	}

	for idx, k := range p.AllowedAccounts {
		p.AllowedAccounts[idx], err = toPublicKey(k, nkeys.PrefixByteAccount)
		if err != nil {
			return err
		}
	}

	for idx, k := range p.RmAllowedAccounts {
		p.RmAllowedAccounts[idx], err = toPublicKey(k, nkeys.PrefixByteAccount)
		if err != nil {
			return err
		}
	}

	return nil
}

func report(list jwt.StringList, toAdd []string, hasMsgT string, missingMsgT string) []string {
	var r = make([]string, len(toAdd))
	for idx, v := range toAdd {
		if list.Contains(v) {
			r[idx] = fmt.Sprintf(hasMsgT, v)
		} else {
			r[idx] = fmt.Sprintf(missingMsgT, v)
		}
	}
	return r
}

func (p *EditAccountCalloutParams) Run(ctx ActionCtx) (store.Status, error) {
	var userReport []string
	var userRmReport []string
	var accountReport []string
	var accountRmReport []string
	var curveReport []string

	if !p.disable {
		userReport = report(p.claim.Account.Authorization.AuthUsers,
			p.AuthUsers,
			"skipped adding user %q - as it's already set",
			"added user %q")

		p.claim.Account.Authorization.AuthUsers.Add(p.AuthUsers...)
		accountReport = report(p.claim.Account.Authorization.AllowedAccounts,
			p.AllowedAccounts,
			"skipped adding account %q - as it's already set",
			"added account %q")
		p.claim.Account.Authorization.AllowedAccounts.Add(p.AllowedAccounts...)

		userRmReport = report(p.claim.Account.Authorization.AuthUsers,
			p.RmAuthUsers,
			"deleted user %q",
			"skipping user %q - as it's not currently set")
		p.claim.Authorization.AuthUsers.Remove(p.RmAuthUsers...)

		accountRmReport = report(p.claim.Account.Authorization.AllowedAccounts,
			p.RmAllowedAccounts,
			"deleted account %q",
			"skipping account %q - as it's not currently set")
		p.claim.Account.Authorization.AllowedAccounts.Remove(p.RmAllowedAccounts...)

		if p.RmXKey {
			old := p.claim.Account.Authorization.XKey
			if old != "" {
				p.claim.Account.Authorization.XKey = ""
				curveReport = append(curveReport, fmt.Sprintf("removed %s curve key", old))
			} else {
				curveReport = append(curveReport, "remove curve key didn't do anything as the curve key was not set")
			}
		}

		if ctx.AnySet("curve") {
			ckeys, err := p.XKey.PublicKeys()
			if err != nil {
				return nil, err
			}
			if len(ckeys) > 1 {
				return nil, errors.New("only one curve key can be specified")
			}
			p.claim.Authorization.XKey = ckeys[0]
			curveReport = append(curveReport, fmt.Sprintf("set curve key %s", ckeys[0]))
		}

	} else {
		p.claim.Account.Authorization = jwt.ExternalAuthorization{}
	}

	// validate before we store it
	var vr jwt.ValidationResults
	p.claim.Validate(&vr)
	errs := vr.Errors()
	if len(errs) > 0 {
		return nil, errs[0]
	}

	// encode and report
	token, err := p.claim.Encode(p.signerKP)
	if err != nil {
		return nil, err
	}

	r := store.NewDetailedReport(false)
	StoreAccountAndUpdateStatus(ctx, token, r)
	if r.HasNoErrors() {
		for _, v := range userReport {
			r.AddOK(v)
		}
		for _, v := range userRmReport {
			r.AddOK(v)
		}
		for _, v := range accountReport {
			r.AddOK(v)
		}
		for _, v := range accountRmReport {
			r.AddOK(v)
		}

		for _, v := range curveReport {
			r.AddOK(v)
		}

		if p.disable {
			r.AddOK("removed external authorization configuration")
		}
	}
	return r, err
}
