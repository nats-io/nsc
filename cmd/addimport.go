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
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/nats-io/nsc/cli"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/spf13/cobra"
)

func createImportCmd() *cobra.Command {
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
			cmd.Printf("Success! - added %s import %q\n", params.activation.Exports[0].Type, params.activation.Exports[0].Subject)
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.accountName, "account-name", "a", "", "account name")
	cmd.Flags().StringVarP(&params.im.Name, "name", "n", "", "import name")
	cmd.Flags().StringVarP(&params.to, "to", "t", "", "target subject")
	cmd.Flags().StringVarP(&params.src, "token", "u", "", "path to token file can be a local path or an url")

	return cmd
}

func init() {
	addCmd.AddCommand(createImportCmd())
}

type AddImportParams struct {
	accountName string
	claim       *jwt.AccountClaims
	activation  *jwt.ActivationClaims
	im          jwt.Import
	operatorKP  nkeys.KeyPair
	to          string
	token       []byte
	src         string
}

func (p *AddImportParams) SetDefaults(ctx ActionCtx) error {
	if p.accountName == "" {
		p.accountName = ctx.StoreCtx().Account.Name
	}

	p.im.To = jwt.Subject(p.to)

	return nil
}

func (p *AddImportParams) PreInteractive(ctx ActionCtx) error {
	var err error

	p.accountName, err = ctx.StoreCtx().PickAccount(p.accountName)
	if err != nil {
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
		r, err := http.Get(p.src)
		if err != nil {
			return nil, fmt.Errorf("error loading %q: %v", p.src, err)
		}
		defer r.Body.Close()
		var buf bytes.Buffer
		_, err = io.Copy(&buf, r.Body)
		if err != nil {
			return nil, fmt.Errorf("error reading response from %q: %v", p.src, err)
		}
		data := buf.Bytes()
		return data, nil
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

	if p.accountName == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return errors.New("an account is required")
	}

	if p.src == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return errors.New("--token is required")
	}

	p.claim, err = ctx.StoreCtx().Store.ReadAccountClaim(p.accountName)
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

	if len(p.activation.Exports) == 0 {
		return fmt.Errorf("activation %q doesn't have any exports", p.src)
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
		p.to = string(p.activation.Exports[0].Subject)
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

	if p.accountName == "" {
		return errors.New("an account is required")
	}

	var export = p.activation.Exports[0]

	for _, im := range p.claim.Imports {
		if im.Account == p.activation.Issuer && string(im.Subject) == string(export.Subject) {
			return fmt.Errorf("account %s already imports %q from %s", p.accountName, im.Subject, p.activation.Issuer)
		}
	}

	if p.im.Name == "" {
		p.im.Name = export.Name
	}
	p.im.Subject = export.Subject
	p.im.Type = export.Type
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
