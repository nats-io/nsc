/*
 *
 *  * Copyright 2018-2019 The NATS Authors
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package cmd

import (
	"errors"
	"fmt"
	"strings"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func CreateAddAccountCmd() *cobra.Command {
	var params AddAccountParams
	cmd := &cobra.Command{
		Use:          "account",
		Short:        "Add an account",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,

		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}
			return GetConfig().SetAccount(params.name)
		},
	}
	cmd.Flags().StringVarP(&params.name, "name", "n", "", "account name")
	cmd.Flags().StringVarP(&params.keyPath, "public-key", "k", "", "public key identifying the account")
	params.TimeParams.BindFlags(cmd)

	return cmd
}

func init() {
	addCmd.AddCommand(CreateAddAccountCmd())
}

type AddAccountParams struct {
	SignerParams
	TimeParams
	token    string
	name     string
	generate bool
	keyPath  string
	akp      nkeys.KeyPair
}

func (p *AddAccountParams) SetDefaults(ctx ActionCtx) error {
	p.name = NameFlagOrArgument(p.name, ctx)
	if p.name == "*" {
		p.name = GetRandomName(0)
	}
	p.generate = p.keyPath == ""
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)
	return nil
}

func (p *AddAccountParams) resolveAccountNKey(s string) (nkeys.KeyPair, error) {
	nk, err := store.ResolveKey(s)
	if err != nil {
		return nil, err
	}
	if nk == nil {
		return nil, fmt.Errorf("a key is required")
	}
	t, err := store.KeyType(nk)
	if err != nil {
		return nil, err
	}
	if t != nkeys.PrefixByteAccount {
		return nil, errors.New("specified key is not a valid account nkey")
	}
	return nk, nil
}

func (p *AddAccountParams) validateAccountNKey(s string) error {
	_, err := p.resolveAccountNKey(s)
	return err
}

func (p *AddAccountParams) PreInteractive(ctx ActionCtx) error {
	var err error
	p.name, err = cli.Prompt("account name", p.name, cli.NewLengthValidator(1))
	if err != nil {
		return err
	}

	p.generate, err = cli.Confirm("generate an account nkey", true)
	if err != nil {
		return err
	}
	if !p.generate {
		p.keyPath, err = cli.Prompt("path to an account nkey or nkey", p.keyPath, cli.Val(p.validateAccountNKey))
		if err != nil {
			return err
		}
	}

	if err = p.TimeParams.Edit(); err != nil {
		return err
	}

	return nil
}

func (p *AddAccountParams) Load(ctx ActionCtx) error {
	var err error
	if p.generate {
		p.akp, err = nkeys.CreateAccount()
		if err != nil {
			return err
		}
		if p.keyPath, err = ctx.StoreCtx().KeyStore.Store(p.akp); err != nil {
			return err
		}
	} else {
		p.akp, err = p.resolveAccountNKey(p.keyPath)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *AddAccountParams) validSigners(ctx ActionCtx) ([]string, error) {
	oc, err := ctx.StoreCtx().Store.ReadOperatorClaim()
	if err != nil {
		return nil, err
	}
	var signers []string
	signers = append(signers, oc.Subject)
	signers = append(signers, oc.SigningKeys...)
	if ctx.StoreCtx().Store.IsManaged() && p.akp != nil {
		pk, err := p.akp.PublicKey()
		if err != nil {
			return nil, err
		}
		signers = append(signers, pk)
	}
	return signers, nil
}

func (p *AddAccountParams) PostInteractive(ctx ActionCtx) error {
	signers, err := p.validSigners(ctx)
	if err != nil {
		return err
	}
	p.SignerParams.SetPrompt("select the key to sign the account")
	return p.SignerParams.SelectFromSigners(ctx, signers)
}

func (p *AddAccountParams) Validate(ctx ActionCtx) error {
	var err error
	if p.name == "" {
		return fmt.Errorf("account name is required")
	}

	if p.name == "*" {
		p.name = GetRandomName(0)
	}

	names, err := GetConfig().ListAccounts()
	if err != nil {
		return err
	}
	found := false
	lcn := strings.ToLower(p.name)
	for _, v := range names {
		if lcn == strings.ToLower(v) {
			found = true
			break
		}
	}
	if found {
		return fmt.Errorf("the account %q already exists", p.name)
	}

	if p.akp == nil {
		return errors.New("path to an account nkey or nkey is required - specify --public-key")
	}

	kt, err := store.KeyType(p.akp)
	if err != nil {
		return err
	}

	if kt != nkeys.PrefixByteAccount {
		return errors.New("invalid account key")
	}

	if err = p.TimeParams.Validate(); err != nil {
		return err
	}

	// the account doesn't exist, so insure self signed works
	p.SignerParams.ForceManagedAccountKey(ctx, p.akp)
	if err := p.SignerParams.Resolve(ctx); err != nil {
		return err
	}

	signers, err := p.validSigners(ctx)
	if err != nil {
		return err
	}
	ok, err := ValidSigner(p.SignerParams.signerKP, signers)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("invalid account signer")
	}
	return nil
}

func (p *AddAccountParams) Run(ctx ActionCtx) (store.Status, error) {
	var err error
	pk, err := p.akp.PublicKey()
	if err != nil {
		return nil, err
	}

	ac := jwt.NewAccountClaims(pk)
	ac.Name = p.name
	if p.TimeParams.IsStartChanged() {
		ac.NotBefore, _ = p.TimeParams.StartDate()
	}

	if p.TimeParams.IsExpiryChanged() {
		ac.Expires, _ = p.TimeParams.ExpiryDate()
	}

	signer := p.akp
	if !ctx.StoreCtx().Store.IsManaged() || p.signerKP != nil {
		signer = p.signerKP
	}
	p.token, err = ac.Encode(signer)
	if err != nil {
		return nil, err
	}

	r := store.NewDetailedReport(false)
	if p.generate {
		r.AddOK("generated and stored account key %q", pk)
	}
	StoreAccountAndUpdateStatus(ctx, p.token, r)
	if r.HasNoErrors() {
		r.AddOK("added account %q", p.name)
	}
	return r, err
}
