/*
 * Copyright 2018-2019 The NATS Authors
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
	"strings"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createAddImportCmd() *cobra.Command {
	var params AddImportParams
	cmd := &cobra.Command{
		Use:          "import",
		Short:        "Add an import",
		Args:         MaxArgs(0),
		Example:      params.longHelp(),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().StringVarP(&params.tokenSrc, "token", "u", "", "path to token file can be a local path or an url (private imports only)")

	cmd.Flags().StringVarP(&params.name, "name", "n", "", "import name")
	cmd.Flags().StringVarP(&params.local, "local-subject", "s", "", "local subject or prefix")
	params.srcAccount.BindFlags("src-account", "", nkeys.PrefixByteAccount, cmd)
	cmd.Flags().StringVarP(&params.remote, "remote-subject", "", "", "remote subject (only public imports)")
	cmd.Flags().BoolVarP(&params.service, "service", "", false, "service (only public imports)")
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	addCmd.AddCommand(createAddImportCmd())
}

type AddImportParams struct {
	AccountContextParams
	SignerParams
	srcAccount PubKeyParams
	claim      *jwt.AccountClaims
	local      string
	token      []byte
	tokenSrc   string
	remote     string
	service    bool
	name       string
	public     bool
}

func (p *AddImportParams) longHelp() string {
	v := `toolname add import -i
toolname add import --token-file path --local-subject <sub>
toolname add import --token https://some.service.com/path --local-subject <sub>
toolname add import --src-account <account_pubkey> --remote-subject <remote-sub> --local-subject <sub>`

	return strings.Replace(v, "toolname", GetToolName(), -1)
}

func (p *AddImportParams) SetDefaults(ctx ActionCtx) error {
	if !InteractiveFlag {
		p.public = ctx.AllSet("token")
		set := ctx.CountSet("token", "remote-subject", "src-account")
		if p.public && set > 1 {
			ctx.CurrentCmd().SilenceErrors = false
			ctx.CurrentCmd().SilenceUsage = false
			return errors.New("private imports require src-account, remote-subject and service to be unset")
		}
		if !p.public && set != 2 {
			ctx.CurrentCmd().SilenceErrors = false
			ctx.CurrentCmd().SilenceUsage = false
			return errors.New("public imports require src-account, remote-subject")
		}
	}

	if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
		return err
	}

	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)

	if p.name == "" {
		p.name = p.remote
	}

	if p.service && p.local == "" {
		p.local = p.remote
	}

	return nil
}

func (p *AddImportParams) getAvailableExports(ctx ActionCtx) ([]AccountExport, error) {
	// these are sorted by account name
	found, err := GetAllExports()
	if err != nil {
		return nil, err
	}

	ac, err := ctx.StoreCtx().Store.ReadAccountClaim(ctx.StoreCtx().Account.Name)
	if err != nil {
		return nil, err
	}

	var filtered []AccountExport
	for _, f := range found {
		// FIXME: filtering on the target account, should eliminate exports the account already has
		if f.Subject != ac.Subject {
			filtered = append(filtered, f)
		}
	}

	return filtered, nil
}

func (p *AddImportParams) addLocalExport(ctx ActionCtx) (bool, error) {
	// see if we have any exports
	available, err := p.getAvailableExports(ctx)
	if err != nil {
		return false, err
	}

	if len(available) > 0 {
		// we have some exports that they may want
		ok, err := cli.Confirm("pick from locally available exports", true)
		if err != nil {
			return false, err
		}
		if ok {
			var choices []AccountExportChoice
			for _, v := range available {
				choices = append(choices, v.Choices()...)
			}
			var labels = AccountExportChoices(choices).String()
			// fixme: need to have validators on this

			var c *AccountExportChoice
			for {
				idx, err := cli.Select("select the export", "", labels)
				if err != nil {
					return false, err
				}
				if choices[idx].Selection == nil {
					ctx.CurrentCmd().Printf("%q is an account grouping not an export\n", labels[idx])
					continue
				}
				c = &choices[idx]
				break
			}

			targetAccountPK := ctx.StoreCtx().Account.PublicKey
			p.srcAccount.publicKey = c.Subject
			p.name = c.Selection.Name

			ac, err := ctx.StoreCtx().Store.ReadAccountClaim(ctx.StoreCtx().Account.Name)
			if err != nil {
				return false, err
			}

			p.claim = ac
			subject := string(c.Selection.Subject)

			if c.Selection.IsService() && c.Selection.Subject.HasWildCards() {
				a := strings.Split(subject, ".")
				for i, e := range a {
					if e == ">" || e == "*" {
						a[i] = targetAccountPK
					}
				}
				subject = strings.Join(a, ".")
				subject, err = cli.Prompt("export subject", subject, cli.Val(func(s string) error {
					sub := jwt.Subject(s)
					if sub.HasWildCards() {
						return errors.New("services cannot have wildcard subjects")
					}
					var vr jwt.ValidationResults
					sub.Validate(&vr)
					if len(vr.Issues) > 0 {
						return errors.New(vr.Issues[0].Description)
					}
					return nil
				}))
				if err != nil {
					return false, err
				}
			}
			p.remote = subject
			p.service = c.Selection.IsService()
			if p.service && p.local == "" {
				p.local = subject
			}
			if c.Selection.TokenReq {
				if err := p.generateToken(ctx, c); err != nil {
					return false, err
				}
			}
			return true, nil
		}
	}
	return false, nil
}

func (p *AddImportParams) generateToken(ctx ActionCtx, c *AccountExportChoice) error {
	// load the source account
	srcAC, err := ctx.StoreCtx().Store.ReadAccountClaim(c.Name)
	if err != nil {
		return err
	}

	var ap GenerateActivationParams
	ap.Name = c.Name
	ap.claims = srcAC
	ap.accountKey.publicKey = ctx.StoreCtx().Account.PublicKey
	ap.export = *c.Selection
	ap.subject = p.remote

	// collect the possible signers
	var signers []string
	signers = append(signers, srcAC.Subject)
	signers = append(signers, srcAC.SigningKeys...)

	ap.SignerParams.SetPrompt(fmt.Sprintf("select the signing key for account %q [%s]", srcAC.Name, srcAC.Subject))
	if err := ap.SelectFromSigners(ctx, signers); err != nil {
		return err
	}

	if _, err := ap.Run(ctx); err != nil {
		return err
	}

	p.token = []byte(ap.Token())
	return p.initFromActivation(ctx)
}

func (p *AddImportParams) addManualExport(ctx ActionCtx) error {
	var err error
	p.public, err = cli.Confirm("is the export public?", true)
	if err != nil {
		return err
	}
	if p.public {
		if err := p.srcAccount.Edit(); err != nil {
			return err
		}
		p.remote, err = cli.Prompt("remote subject", p.remote, cli.Val(func(v string) error {
			t := jwt.Subject(v)
			var vr jwt.ValidationResults
			t.Validate(&vr)
			if len(vr.Issues) > 0 {
				return errors.New(vr.Issues[0].Description)
			}
			return nil
		}))
		p.service, err = cli.Confirm("is import a service", true)
		if err != nil {
			return err
		}
	} else {
		p.tokenSrc, err = cli.Prompt("token path or url", p.tokenSrc, cli.Val(func(s string) error {
			p.tokenSrc = s
			p.token, err = p.loadImport()
			if err != nil {
				return err
			}
			return nil
		}))
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *AddImportParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}

	ok, err := p.addLocalExport(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return p.addManualExport(ctx)
	}

	return nil
}

func (p *AddImportParams) loadImport() ([]byte, error) {
	data, err := LoadFromFileOrURL(p.tokenSrc)
	if err != nil {
		return nil, fmt.Errorf("error loading %#q: %v", p.tokenSrc, err)
	}
	v, err := jwt.ParseDecoratedJWT(data)
	if err != nil {
		return nil, fmt.Errorf("error loading %#q: %v", p.tokenSrc, err)
	}
	return []byte(v), nil
}

func (p *AddImportParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	p.claim, err = ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		return err
	}

	if p.tokenSrc != "" {
		if err := p.initFromActivation(ctx); err != nil {
			return err
		}
	}

	return nil
}

func (p *AddImportParams) initFromActivation(ctx ActionCtx) error {
	var err error
	if p.token == nil {
		p.token, err = p.loadImport()
		if err != nil {
			return err
		}
	}

	ac, err := jwt.DecodeActivationClaims(string(p.token))
	if err != nil {
		return err
	}

	if p.name == "" {
		p.name = ac.Name
	}
	p.remote = string(ac.ImportSubject)
	p.service = ac.ImportType == jwt.Service
	if p.service && p.local == "" {
		p.local = p.remote
	}

	p.srcAccount.publicKey = ac.Issuer
	if ac.IssuerAccount != "" {
		p.srcAccount.publicKey = ac.IssuerAccount
	}
	if ac.Subject != "public" && p.claim.Subject != ac.Subject {
		return fmt.Errorf("activation is not intended for this account - it is for %q", ac.Subject)
	}
	return nil
}

func (p *AddImportParams) checkServiceSubject(s string) error {
	// if we are not dealing with a service ignore
	if !p.service {
		return nil
	}
	for _, v := range p.claim.Imports {
		// ignore streams
		if v.IsStream() {
			continue
		}
		if s == string(v.Subject) {
			return fmt.Errorf("%s is already in use by a different service import", s)
		}
	}
	return nil
}

func (p *AddImportParams) PostInteractive(ctx ActionCtx) error {
	var err error

	if p.name == "" {
		p.name = p.remote
	}

	p.name, err = cli.Prompt("name", p.name, cli.NewLengthValidator(1))
	if err != nil {
		return err
	}
	if p.local == "" {
		p.local = p.remote
	}

	// services have to have a local subject - streams can be blank and import on source subject
	m := "stream prefix subject"
	prefix := ""
	if p.service {
		m = "local subject"
		prefix = p.local
	}
	p.local, err = cli.Prompt(m, prefix, cli.Val(func(s string) error {
		if !p.service && s == "" {
			return nil
		}
		if err := p.checkServiceSubject(s); err != nil {
			return err
		}

		vr := jwt.CreateValidationResults()
		sub := jwt.Subject(s)
		sub.Validate(vr)
		if !vr.IsEmpty() {
			return errors.New(vr.Issues[0].Error())
		}

		if sub.HasWildCards() {
			return fmt.Errorf("%s cannot have wildcards", m)
		}

		return nil
	}))
	if err != nil {
		return err
	}

	if err = p.SignerParams.Edit(ctx); err != nil {
		return err
	}

	return nil
}

func (p *AddImportParams) Validate(ctx ActionCtx) error {
	var err error

	if p.claim.Subject == p.srcAccount.publicKey {
		return fmt.Errorf("export issuer is this account")
	}

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	if err = p.srcAccount.Valid(); err != nil {
		return err
	}

	kind := jwt.Stream
	if p.service {
		kind = jwt.Service
	}

	// local becomes Subject for services, or prefix for streams
	sub := jwt.Subject(p.local)
	if sub.HasWildCards() {
		if kind == jwt.Service {
			return errors.New("local subject cannot have wildcards")
		} else {
			return errors.New("stream prefix subject cannot have wildcards")
		}
	}

	resub := jwt.Subject(p.remote)
	if kind == jwt.Service && resub.HasWildCards() {
		return errors.New("imported services cannot have wildcards")
	}

	for _, im := range p.filter(kind, p.claim.Imports) {
		remote := string(im.Subject)
		if im.Type == jwt.Service {
			remote = string(im.To)
		}
		if im.Account == p.srcAccount.publicKey && remote == p.remote {
			return fmt.Errorf("account already imports %s %q from %s", kind, im.Subject, p.srcAccount.publicKey)
		}
	}

	if err = p.SignerParams.Resolve(ctx); err != nil {
		return err
	}

	return nil
}

func (p *AddImportParams) filter(kind jwt.ExportType, imports jwt.Imports) jwt.Imports {
	var buf jwt.Imports
	for _, v := range imports {
		if v.Type == kind {
			buf.Add(v)
		}
	}
	return buf
}

func (p *AddImportParams) Run(ctx ActionCtx) (store.Status, error) {
	var err error
	p.claim.Imports.Add(p.createImport())

	token, err := p.claim.Encode(p.signerKP)
	if err != nil {
		return nil, err
	}

	ac, err := jwt.DecodeAccountClaims(token)
	if err != nil {
		return nil, err
	}

	var vr jwt.ValidationResults
	ac.Validate(&vr)
	errs := vr.Errors()
	if len(errs) > 0 {
		return nil, errs[0]
	}

	kind := jwt.Stream
	if p.service {
		kind = jwt.Service
	}

	r := store.NewDetailedReport(false)
	StoreAccountAndUpdateStatus(ctx, token, r)
	if r.HasNoErrors() {
		r.AddOK("added %s import %q", kind, p.remote)
	}
	return r, err
}

func (p *AddImportParams) createImport() *jwt.Import {
	var im jwt.Import
	im.Name = p.name
	im.Subject = jwt.Subject(p.remote)
	im.To = jwt.Subject(p.local)
	im.Account = p.srcAccount.publicKey
	im.Type = jwt.Stream

	if p.service {
		im.Type = jwt.Service
		im.Subject, im.To = im.To, im.Subject
	}
	if p.tokenSrc != "" {
		if IsURL(p.tokenSrc) {
			im.Token = p.tokenSrc
		}
	}
	if p.token != nil {
		im.Token = string(p.token)
	}

	return &im
}
