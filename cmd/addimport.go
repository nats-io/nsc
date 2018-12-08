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
	"io/ioutil"
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
		Args:         cobra.MaximumNArgs(0),
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
				cmd.Printf("Success! - added %s import %q\n", kind, params.srcSubject)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.src, "token", "u", "", "path to token file can be a local path or an url (private imports only)")

	cmd.Flags().StringVarP(&params.name, "name", "n", "", "import name")
	cmd.Flags().StringVarP(&params.to, "to", "t", "", "target subject")

	cmd.Flags().StringVarP(&params.srcAccount, "src-account", "", "", "source account (only public imports)")
	cmd.Flags().StringVarP(&params.srcSubject, "src-subject", "", "", "source subject (only public imports)")
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
	claim      *jwt.AccountClaims
	to         string
	token      []byte
	src        string
	srcAccount string
	srcSubject string
	service    bool
	name       string
}

func (p *AddImportParams) longHelp() string {
	v := `toolname add import -i
toolname add import --token-file path --to <sub>
toolname add import --token https://some.service.com/path --to <sub>
toolname add import --src-account <account_pubkey> --src-subject <src_subject> --to <sub>`

	return strings.Replace(v, "toolname", GetToolName(), -1)
}

func (p *AddImportParams) SetDefaults(ctx ActionCtx) error {
	if !InteractiveFlag {
		tokenSet := ctx.AllSet("token")
		set := ctx.CountSet("token", "src-subject", "src-account")
		if tokenSet && set > 1 {
			ctx.CurrentCmd().SilenceErrors = false
			ctx.CurrentCmd().SilenceUsage = false
			return errors.New("private imports require src-account, src-subject and service to be unset")
		}
		if !tokenSet && set != 2 {
			ctx.CurrentCmd().SilenceErrors = false
			ctx.CurrentCmd().SilenceUsage = false
			return errors.New("public imports require src-account, src-subject")
		}
	}

	if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
		return err
	}

	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)

	if p.name == "" {
		p.name = p.srcSubject
	}

	return nil
}

func (p *AddImportParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}

	p.service, err = cli.PromptYN("is the export public?")
	if err != nil {
		return err
	}
	if p.service {
		p.srcAccount, err = cli.Prompt("source account", p.srcAccount, true, func(s string) error {
			if !nkeys.IsValidPublicAccountKey(s) {
				return errors.New("not a valid account public key")
			}
			return nil
		})
		if err != nil {
			return err
		}
		p.srcSubject, err = cli.Prompt("source subject", p.srcSubject, true, func(v string) error {
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
		p.src, err = cli.Prompt("token path or url", p.src, true, func(s string) error {
			p.src = s
			p.token, err = p.LoadImport()
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

func (p *AddImportParams) LoadImport() ([]byte, error) {
	if url, err := url.Parse(p.src); err == nil && url.Scheme != "" {
		return LoadFromURL(p.src)
	} else {
		data, err := ioutil.ReadFile(p.src)
		if err != nil {
			return nil, fmt.Errorf("error loading %q: %v", p.src, err)
		}
		v, _ := ExtractToken(string(data))
		if err != nil {
			return nil, fmt.Errorf("error loading %q: %v", p.src, err)
		}
		return []byte(v), nil
	}
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

	if p.src != "" {
		if err := p.initFromExport(ctx); err != nil {
			return err
		}
	}

	return nil
}

func (p *AddImportParams) initFromExport(ctx ActionCtx) error {
	var err error
	if p.token == nil {
		p.token, err = p.LoadImport()
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

	p.srcSubject = string(ac.ImportSubject)

	if p.to == "" {
		p.to = p.srcSubject
	}

	if ac.ImportType == jwt.Service {
		p.service = true
	}

	p.srcAccount = ac.Issuer

	if ac.Subject != "public" && p.claim.Subject != ac.Subject {
		return fmt.Errorf("activation is not intended for this account - it is for %q", ac.Subject)
	}
	return nil
}

func (p *AddImportParams) PostInteractive(ctx ActionCtx) error {
	var err error

	p.name, err = cli.Prompt("import name", p.name, true, cli.LengthValidator(1))
	if err != nil {
		return err
	}

	if p.to == "" {
		p.to = p.srcSubject
	}

	p.to, err = cli.Prompt("subject mapping", p.to, true, func(s string) error {
		vr := jwt.CreateValidationResults()
		sub := jwt.Subject(s)
		sub.Validate(vr)
		if !vr.IsEmpty() {
			return errors.New(vr.Issues[0].Error())
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

func (p *AddImportParams) createImport() *jwt.Import {
	var im jwt.Import
	im.Name = p.name
	im.Subject = jwt.Subject(p.srcSubject)
	im.Account = p.srcAccount

	if p.src != "" {
		if u, err := url.Parse(p.src); err == nil && u.Scheme != "" {
			im.Token = p.src
		} else {
			im.Token = string(p.token)
		}
	}
	im.To = jwt.Subject(p.to)

	kind := jwt.Stream
	if p.service {
		kind = jwt.Service
	}
	im.Type = kind

	return &im
}

func (p *AddImportParams) Validate(ctx ActionCtx) error {
	var err error

	if p.claim.Subject == p.srcAccount {
		return fmt.Errorf("export issuer is this account")
	}

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	kind := jwt.Stream
	if p.service {
		kind = jwt.Service
	}

	for _, im := range p.claim.Imports {
		if im.Account == p.srcAccount &&
			string(im.Subject) == string(p.srcSubject) &&
			im.Type == kind {
			return fmt.Errorf("account already imports %s %q from %s", kind, im.Subject, p.srcAccount)
		}
	}

	if err = p.SignerParams.Resolve(ctx); err != nil {
		return err
	}

	return nil
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
