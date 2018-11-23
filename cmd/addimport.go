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

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
	"github.com/spf13/cobra"
)

func createAddImportCmd() *cobra.Command {
	var params AddImportParams
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Add an import",
		Example: `nsc add import -i
nsc add import --token-file path --to import.>
nsc add import --url https://some.service.com/path --to import.>`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}
			cmd.Printf("Success! - added %s import %q\n", params.activation.Activation.ImportType, params.activation.Activation.ImportSubject)
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.im.Name, "name", "n", "", "import name")
	cmd.Flags().StringVarP(&params.to, "to", "t", "", "target subject")
	cmd.Flags().StringVarP(&params.src, "token", "u", "", "path to token file can be a local path or an url")
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	addCmd.AddCommand(createAddImportCmd())
}

type AddImportParams struct {
	AccountContextParams
	claim      *jwt.AccountClaims
	activation *jwt.ActivationClaims
	im         jwt.Import
	operatorKP nkeys.KeyPair
	to         string
	token      []byte
	src        string
}

func (p *AddImportParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.SetDefaults(ctx)
	p.im.To = jwt.Subject(p.to)

	return nil
}

func (p *AddImportParams) PreInteractive(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}

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
		v := ExtractToken(string(data))
		return []byte(v), nil
	}
}

func (p *AddImportParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	if p.src == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return errors.New("token is required")
	}

	p.claim, err = ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		return err
	}

	if p.token == nil {
		p.token, err = p.LoadImport()
		if err != nil {
			return err
		}
	}

	p.activation, err = jwt.DecodeActivationClaims(string(p.token))
	if err != nil {
		return err
	}

	if p.claim.Subject == p.activation.Issuer {
		return fmt.Errorf("activation issuer is this account")
	}

	if p.activation.Subject != "public" && p.claim.Subject != p.activation.Subject {
		return fmt.Errorf("activation is not intended for this account - it is for %q", p.activation.Subject)
	}

	// FIXME: validation issues on the loaded activation - jwt needs to return some sort of error we can render

	return nil
}

func (p *AddImportParams) PostInteractive(ctx ActionCtx) error {
	var err error

	p.im.Name, err = cli.Prompt("import name", p.activation.Name, true, cli.LengthValidator(1))
	if err != nil {
		return err
	}

	if p.to == "" {
		p.to = string(p.activation.Activation.ImportSubject)
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
	p.im.To = jwt.Subject(p.to)

	p.operatorKP, err = ctx.StoreCtx().ResolveKey(nkeys.PrefixByteOperator, KeyPathFlag)
	if err != nil {
		return err
	}
	if p.operatorKP == nil {
		err = EditKeyPath(nkeys.PrefixByteOperator, "operator keypath", &KeyPathFlag)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *AddImportParams) Validate(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	var export = p.activation.Activation

	for _, im := range p.claim.Imports {
		if im.Account == p.activation.Issuer && string(im.Subject) == string(export.ImportSubject) {
			return fmt.Errorf("account %s already imports %q from %s", p.AccountContextParams.Name, im.Subject, p.activation.Issuer)
		}
	}

	if p.im.Name == "" {
		p.im.Name = string(p.im.Subject)
	}
	p.im.Subject = export.ImportSubject
	p.im.Type = export.ImportType
	p.im.Account = p.activation.Issuer
	p.im.To = jwt.Subject(p.to)
	if url, err := url.Parse(p.src); err == nil && url.Scheme != "" {
		p.im.Token = p.src
	} else {
		p.im.Token = string(p.token)
	}

	p.operatorKP, err = ctx.StoreCtx().ResolveKey(nkeys.PrefixByteOperator, KeyPathFlag)
	if err != nil {
		return err
	}
	return nil
}

func (p *AddImportParams) Run(ctx ActionCtx) error {
	var err error
	p.claim.Imports.Add(&p.im)
	token, err := p.claim.Encode(p.operatorKP)
	if err != nil {
		return err
	}
	return ctx.StoreCtx().Store.StoreClaim([]byte(token))
}
