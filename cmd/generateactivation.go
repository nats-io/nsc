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
	"net/url"
	"path"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createGenerateActivationCmd() *cobra.Command {
	var params GenerateActivationParams
	cmd := &cobra.Command{
		Use:          "activation",
		Short:        "Generate an export activation jwt token",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().StringVarP(&params.subject, "subject", "s", "", "export subject")
	cmd.Flags().StringVarP(&params.out, "output-file", "o", "--", "output file '--' is stdout")
	cmd.Flags().BoolVarP(&params.push, "push", "", false, "push activation token to operator's account server (exclusive of output-file")
	params.accountKey.BindFlags("target-account", "t", nkeys.PrefixByteAccount, cmd)
	params.timeParams.BindFlags(cmd)
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	generateCmd.AddCommand(createGenerateActivationCmd())
}

type GenerateActivationParams struct {
	AccountContextParams
	SignerParams
	accountKey     PubKeyParams
	activation     *jwt.ActivationClaims
	claims         *jwt.AccountClaims
	export         jwt.Export
	privateExports []AccountExportChoice
	timeParams     TimeParams
	token          string
	out            string
	push           bool
	subject        string
}

func (p *GenerateActivationParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.SetDefaults(ctx)
	p.SignerParams.SetDefaults(nkeys.PrefixByteAccount, false, ctx)
	return nil
}

func (p *GenerateActivationParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}
	return nil
}

func (p *GenerateActivationParams) Load(ctx ActionCtx) error {
	var err error
	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	p.claims, err = ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		return err
	}

	if len(p.claims.Exports) == 0 {
		return fmt.Errorf("account %q doesn't have exports", p.AccountContextParams.Name)
	}

	choices, err := GetAccountExports(p.claims)
	if err != nil {
		return err
	}
	for _, e := range choices {
		if e.Selection.TokenReq {
			p.privateExports = append(p.privateExports, e)
		}
	}
	if len(p.privateExports) == 0 {
		return fmt.Errorf("account %q doesn't have exports that require an activation token", p.AccountContextParams.Name)
	}

	if len(p.privateExports) == 1 && p.subject == "" {
		p.subject = string(p.privateExports[0].Selection.Subject)
	}

	return nil
}

func (p *GenerateActivationParams) PostInteractive(ctx ActionCtx) error {
	var err error

	labels := AccountExportChoices(p.privateExports).String()
	choice := ""
	if len(labels) == 1 {
		choice = labels[0]
	}
	i, err := cli.Select("select the export", choice, labels)
	if err != nil {
		return err
	}

	p.export = *p.privateExports[i].Selection
	if p.subject == "" {
		p.subject = string(p.export.Subject)
	}
	kind := p.export.Type

	p.subject, err = cli.Prompt("subject", p.subject, cli.Val(func(v string) error {
		t := jwt.Subject(v)
		var vr jwt.ValidationResults
		t.Validate(&vr)
		if len(vr.Issues) > 0 {
			return errors.New(vr.Issues[0].Description)
		}
		if kind == jwt.Service && t.HasWildCards() {
			return errors.New("services cannot have wildcards")
		}
		if t != p.export.Subject && !t.IsContainedIn(p.export.Subject) {
			return fmt.Errorf("%q doesn't contain %q", string(p.export.Subject), string(t))
		}
		return nil
	}))
	if err != nil {
		return err
	}

	if err = p.accountKey.Edit(); err != nil {
		return err
	}
	if err := p.timeParams.Edit(); err != nil {
		return err
	}
	if err = p.SignerParams.Edit(ctx); err != nil {
		return err
	}

	oc, err := ctx.StoreCtx().Store.ReadOperatorClaim()
	if err != nil {
		return err
	}
	if oc.AccountServerURL != "" {
		m := fmt.Sprintf("push the activation to %q", oc.AccountServerURL)
		p.push, err = cli.Confirm(m, false)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *GenerateActivationParams) Validate(ctx ActionCtx) error {
	var err error

	if p.subject == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return errors.New("a subject is required")
	}

	if err = p.timeParams.Validate(); err != nil {
		return err
	}

	if err = p.accountKey.Valid(); err != nil {
		return err
	}

	// validate the raw subject
	sub := jwt.Subject(p.subject)
	var vr jwt.ValidationResults
	sub.Validate(&vr)
	if len(vr.Issues) > 0 {
		return errors.New(vr.Issues[0].Description)
	}

	for _, e := range p.privateExports {
		if sub.IsContainedIn(e.Selection.Subject) {
			p.export = *e.Selection
			break
		}
	}

	if p.export.Type == jwt.Service && sub.HasWildCards() {
		return fmt.Errorf("services cannot have wildcards %q", p.subject)
	}

	if p.export.Subject == "" {
		return fmt.Errorf("a private export for %q was not found in account %q", p.subject, p.AccountContextParams.Name)
	}

	if err = p.SignerParams.Resolve(ctx); err != nil {
		return err
	}
	return nil
}

func (p *GenerateActivationParams) Run(ctx ActionCtx) (store.Status, error) {
	var err error
	p.activation = jwt.NewActivationClaims(p.accountKey.publicKey)
	p.activation.NotBefore, _ = p.timeParams.StartDate()
	p.activation.Expires, _ = p.timeParams.ExpiryDate()
	p.activation.Name = p.subject
	// p.subject is subset of the export
	p.activation.Activation.ImportSubject = jwt.Subject(p.subject)
	p.activation.Activation.ImportType = p.export.Type

	spub, err := p.signerKP.PublicKey()
	if err != nil {
		return nil, err
	}
	if p.claims.Subject != spub {
		p.activation.IssuerAccount = p.claims.Subject
	}

	p.token, err = p.activation.Encode(p.signerKP)
	if err != nil {
		return nil, err
	}

	d, err := jwt.DecorateJWT(p.token)
	if err != nil {
		return nil, err
	}
	r := store.NewDetailedReport(true)
	r.AddOK("generated %q activation for account %q", p.export.Name, p.accountKey.publicKey)
	if p.activation.NotBefore > 0 {
		r.AddOK("token valid %s - %s", UnixToDate(p.activation.NotBefore), HumanizedDate(p.activation.NotBefore))
	}
	if p.activation.Expires > 0 {
		r.AddOK("token expires %s - %s", UnixToDate(p.activation.Expires), HumanizedDate(p.activation.Expires))
	}

	// if some command embeds, the output will be blank
	// in that case don't generate the output
	if p.out != "" {
		if err := Write(p.out, d); err != nil {
			return nil, err
		}
		if !IsStdOut(p.out) {
			r.AddOK("wrote account description to %#q", AbbrevHomePaths(p.out))
		}
	}

	if p.push {
		oc, err := ctx.StoreCtx().Store.ReadOperatorClaim()
		if err != nil {
			return nil, err
		}
		if oc.AccountServerURL == "" {
			return nil, fmt.Errorf("operator %s doesn't have an account server url configured", oc.Name)
		}
		u, err := url.Parse(oc.AccountServerURL)
		if err != nil {
			return nil, err
		}
		u.Path = path.Join(u.Path, "activations")
		s, err := store.PushAccount(u.String(), []byte(p.token))
		if s != nil {
			r.Add(s)
		}
		if err != nil {
			return s, err
		}

		hid, err := p.activation.HashID()
		if err != nil {
			r.AddError("error calculating activation hash id: %v", err)
			return r, err
		}

		gu, err := url.Parse(oc.AccountServerURL)
		if err != nil {
			return nil, err
		}

		u.Path = path.Join(gu.Path, "activations", hid)
		r.AddOK("activation accessible at %q", u.String())
	}

	return r, nil
}

func (p *GenerateActivationParams) Token() string {
	return p.token
}
