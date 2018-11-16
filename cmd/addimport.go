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
		Example: `nsc add import --token-file path --to import.>
nsc add import --url https://some.service.com/path --to import.>`,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := params.Init(); err != nil {
				return err
			}

			if InteractiveFlag {
				if err := params.Interactive(); err != nil {
					return err
				}
			}

			if err := params.Validate(); err != nil {
				return err
			}

			if err := params.Run(); err != nil {
				return err
			}

			cmd.Printf("Success! - added %s import %q\n", params.Import.Type, params.Import.Name)

			return nil
		},
	}
	cmd.Flags().StringVarP(&params.accountName, "account-name", "a", "", "account name")
	cmd.Flags().StringVarP(&params.Import.Name, "name", "", "", "import name")
	cmd.Flags().StringVarP(&params.Import.TokenURL, "token-url", "u", "", "token url")
	cmd.Flags().StringVarP(&params.to, "to", "t", "", "target subject")
	cmd.Flags().StringVarP(&params.tokenFile, "token-file", "f", "", "token file")

	return cmd
}

func init() {
	addCmd.AddCommand(createImportCmd())
}

type AddImportParams struct {
	jwt.Import
	accountName string
	claim       *jwt.AccountClaims
	operatorKP  nkeys.KeyPair
	to          string
	tokenFile   string

	token []byte
}

func (p *AddImportParams) Init() error {
	s, err := GetStore()
	if err != nil {
		return err
	}

	if p.accountName == "" {
		ctx, err := s.GetContext()
		if err != nil {
			return err
		}
		p.accountName = ctx.Account.Name
	}

	p.Import.To = jwt.Subject(p.to)

	return nil
}

func (p *AddImportParams) Interactive() error {
	var err error

	p.Name, err = cli.Prompt("import name", p.Name, true, cli.LengthValidator(1))
	if err != nil {
		return err
	}

	choices := []string{"file", "url"}
	i, err := cli.PromptChoices("import from", choices)
	switch choices[i] {
	case "file":
		p.tokenFile, err = cli.Prompt("enter the path to the file", p.tokenFile, true, func(s string) error {
			p.tokenFile = s
			p.token, err = p.LoadImport()
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	case "url":
		p.TokenURL, err = cli.Prompt("enter the url to the token", p.tokenFile, true, func(s string) error {
			p.tokenFile = s
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
	p.To = jwt.Subject(p.to)

	return nil
}

func (p *AddImportParams) LoadImport() ([]byte, error) {
	var err error
	var data []byte
	if p.tokenFile != "" {
		data, err = ioutil.ReadFile(p.tokenFile)
		v := ExtractToken(string(data))
		data = []byte(v)
		if err != nil {
			return nil, fmt.Errorf("error loading %q: %v", p.tokenFile, err)
		}
	} else if p.TokenURL != "" {
		r, err := http.Get(p.TokenURL)
		if err != nil {
			return nil, fmt.Errorf("error loading %q: %v", p.TokenURL, err)
		}
		defer r.Body.Close()
		var buf bytes.Buffer
		_, err = io.Copy(&buf, r.Body)
		if err != nil {
			return nil, fmt.Errorf("error reading response from %q: %v", p.TokenURL, err)
		}
		data = buf.Bytes()
	}
	return data, nil
}

func (p *AddImportParams) Validate() error {
	var err error

	if p.TokenURL == "" && p.tokenFile == "" {
		return errors.New("specify --token-url or --token-file ")
	}

	if p.token == nil {
		if p.token, err = p.LoadImport(); err != nil {
			return err
		}
	}

	ac, err := jwt.DecodeActivationClaims(string(p.token))
	if err != nil {
		return fmt.Errorf("error decoding activation: %v", err)
	}

	s, err := GetStore()
	if err != nil {
		return err
	}

	if p.accountName == "" {
		return errors.New("an account is required")
	}

	var export *jwt.Export
	if len(ac.Exports) > 0 {
		export = ac.Exports[0]
	}
	if export == nil {
		return fmt.Errorf("no exports found in the token")
	}

	if p.Import.Name == "" {
		p.Import.Name = export.Name
	}
	p.Import.NamedSubject = export.NamedSubject
	p.Import.Type = export.Type
	p.Import.Account = ac.Issuer
	p.Import.To = jwt.Subject(p.to)
	if p.tokenFile != "" {
		p.Import.Token = string(p.token)
	}

	p.claim, err = s.ReadAccountClaim(p.accountName)
	if err != nil {
		return err
	}

	if p.claim.Subject == p.Import.Account {
		return fmt.Errorf("import account is this account")
	}

	ctx, err := s.GetContext()
	if err != nil {
		return err
	}

	p.operatorKP, err = ctx.ResolveKey(nkeys.PrefixByteOperator, KeyPathFlag)
	if err != nil {
		return err
	}
	return nil
}

func (p *AddImportParams) Run() error {
	s, err := GetStore()
	if err != nil {
		return nil
	}

	p.claim.Imports.Add(&p.Import)
	token, err := p.claim.Encode(p.operatorKP)
	return s.StoreClaim([]byte(token))
}
