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
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
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
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}
			if !QuietMode() {
				kind := jwt.Stream
				if params.service {
					kind = jwt.Service
				}
				cmd.Printf("Success! - added %s import %q\n", kind, params.remote)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.tokenSrc, "token", "u", "", "path to token file can be a local path or an url (private imports only)")

	cmd.Flags().StringVarP(&params.name, "name", "n", "", "import name")
	cmd.Flags().StringVarP(&params.local, "local-subject", "s", "", "local subject")
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

	if p.local == "" {
		p.local = p.remote
	}

	if p.name == "" {
		p.name = p.local
	}

	return nil
}

func (p *AddImportParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}

	p.public, err = cli.PromptYN("is the export public?")
	if err != nil {
		return err
	}
	if p.public {
		if err := p.srcAccount.Edit(); err != nil {
			return err
		}
		p.remote, err = cli.Prompt("remote subject", p.remote, true, func(v string) error {
			t := jwt.Subject(v)
			var vr jwt.ValidationResults
			t.Validate(&vr)
			if len(vr.Issues) > 0 {
				return errors.New(vr.Issues[0].Description)
			}
			return nil
		})
		p.service, err = cli.PromptYN("is import a service")
		if err != nil {
			return err
		}
	} else {
		p.tokenSrc, err = cli.Prompt("token path or url", p.tokenSrc, true, func(s string) error {
			p.tokenSrc = s
			p.token, err = p.loadImport()
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *AddImportParams) loadImport() ([]byte, error) {
	ac, err := jwt.DecodeActivationClaims(p.tokenSrc)
	if ac != nil && err == nil {
		return []byte(p.tokenSrc), nil
	}

	if u, err := url.Parse(p.tokenSrc); err == nil && u.Scheme != "" {
		return LoadFromURL(p.tokenSrc)
	}

	data, err := Read(p.tokenSrc)
	if err != nil {
		return nil, fmt.Errorf("error loading %q: %v", p.tokenSrc, err)
	}
	v, _ := ExtractToken(string(data))
	if err != nil {
		return nil, fmt.Errorf("error loading %q: %v", p.tokenSrc, err)
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
	if p.local == "" {
		p.local = p.remote
	}

	if ac.ImportType == jwt.Service {
		p.service = true
	}

	p.srcAccount.publicKey = ac.Issuer

	if ac.Subject != "public" && p.claim.Subject != ac.Subject {
		return fmt.Errorf("activation is not intended for this account - it is for %q", ac.Subject)
	}
	return nil
}

func (p *AddImportParams) PostInteractive(ctx ActionCtx) error {
	var err error

	p.name, err = cli.Prompt("name", p.name, true, cli.LengthValidator(1))
	if err != nil {
		return err
	}

	if p.local == "" {
		p.local = p.remote
	}
	p.local, err = cli.Prompt("local subject", p.local, true, func(s string) error {
		vr := jwt.CreateValidationResults()
		sub := jwt.Subject(s)
		sub.Validate(vr)
		if !vr.IsEmpty() {
			return errors.New(vr.Issues[0].Error())
		}

		if p.service && sub.HasWildCards() {
			return errors.New("imported services cannot have wildcards")
		}

		return nil
	})
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

	sub := jwt.Subject(p.local)
	if kind == jwt.Service && sub.HasWildCards() {
		return errors.New("imported services cannot have wildcards")
	}

	resub := jwt.Subject(p.remote)
	if kind == jwt.Service && resub.HasWildCards() {
		return errors.New("imported services cannot have wildcards")
	}

	for _, im := range p.filter(kind, p.claim.Imports) {
		local := string(im.To)
		remote := string(im.Subject)
		if im.Type == jwt.Service {
			local, remote = remote, local
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

func (p *AddImportParams) Run(ctx ActionCtx) error {
	var err error
	p.claim.Imports.Add(p.createImport())
	token, err := p.claim.Encode(p.signerKP)
	if err != nil {
		return err
	}

	ac, err := jwt.DecodeAccountClaims(token)
	if err != nil {
		return err
	}
	var vr jwt.ValidationResults
	ac.Validate(&vr)
	errs := vr.Errors()
	if len(errs) > 0 {
		return errs[0]
	}

	return ctx.StoreCtx().Store.StoreClaim([]byte(token))
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
		if u, err := url.Parse(p.tokenSrc); err == nil && u.Scheme != "" {
			im.Token = p.tokenSrc
		} else {
			im.Token = string(p.token)
		}
	}

	return &im
}
