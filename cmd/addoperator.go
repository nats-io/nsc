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
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createAddOperatorCmd() *cobra.Command {
	var params AddOperatorParams
	cmd := &cobra.Command{
		Use:          "operator",
		Short:        "Add an operator",
		SilenceUsage: true,

		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunStoreLessAction(cmd, args, &params); err != nil {
				return err
			}
			if params.generate {
				cmd.Printf("Generated operator key - private key stored %q\n", AbbrevHomePaths(params.keyPath))
			}
			verb := "added"
			if params.jwtPath != "" {
				verb = "imported"
			}
			cmd.Printf("Success! - %s operator %q\n", verb, params.name)

			return nil
		},
	}
	cmd.Flags().StringVarP(&params.name, "name", "n", "", "operator name")
	cmd.Flags().StringVarP(&params.jwtPath, "import", "", "", "import from jwt")
	params.TimeParams.BindFlags(cmd)

	return cmd
}

func init() {
	addCmd.AddCommand(createAddOperatorCmd())
}

type AddOperatorParams struct {
	SignerParams
	TimeParams
	jwtPath  string
	token    string
	name     string
	generate bool
	keyPath  string
}

func (p *AddOperatorParams) SetDefaults(ctx ActionCtx) error {
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, false, ctx)

	if p.name != "" && p.jwtPath != "" {
		return errors.New("specify either name or import")
	}

	return nil
}

func (p *AddOperatorParams) PreInteractive(ctx ActionCtx) error {
	var err error

	ok, err := cli.PromptYN("import operator from a JWT")
	if err != nil {
		return err
	}
	if ok {
		_, err := cli.Prompt("path to operator jwt", p.jwtPath, true, func(s string) error {
			p.jwtPath, err = homedir.Expand(s)
			if err != nil {
				return err
			}
			p.jwtPath, err = filepath.Abs(p.jwtPath)
			if err != nil {
				return err
			}

			info, err := os.Lstat(p.jwtPath)
			if err != nil && !os.IsNotExist(err) {
				return err
			}

			if !info.Mode().IsRegular() {
				return errors.New("path is not a file")
			}
			return nil
		})

		if err != nil {
			return err
		}
	} else {
		p.name, err = cli.Prompt("operator name", p.name, true, cli.LengthValidator(1))
		if err != nil {
			return err
		}
		if err = p.TimeParams.Edit(); err != nil {
			return err
		}
	}

	return nil
}

func (p *AddOperatorParams) Load(ctx ActionCtx) error {
	if p.jwtPath != "" {
		d, err := Read(p.jwtPath)
		if err != nil {
			return fmt.Errorf("error reading %q: %v", p.jwtPath, err)
		}
		s := string(d)
		t, _ := ExtractToken(s)
		op, err := jwt.DecodeOperatorClaims(t)
		if err != nil {
			return fmt.Errorf("error importing operator jwt: %v", err)
		}
		p.token = t
		p.name = op.Name
	}
	return nil
}

func (p *AddOperatorParams) PostInteractive(ctx ActionCtx) error {
	var err error

	if p.token != "" {
		// nothing to generate
		return nil
	}

	if p.signerKP == nil {
		p.generate, err = cli.PromptYN("generate an operator nkey")
		if err != nil {
			return err
		}
		if !p.generate {
			if err := p.SignerParams.Edit(ctx); err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *AddOperatorParams) Validate(ctx ActionCtx) error {
	var err error
	if p.token != "" {
		// validated on load
		return nil
	}
	if p.name == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return fmt.Errorf("operator name is required")
	}

	if err = p.TimeParams.Validate(); err != nil {
		return err
	}

	if err := p.Resolve(ctx); err != nil {
		return err
	}

	if p.signerKP == nil {
		p.generate = true
		p.signerKP, err = nkeys.CreateOperator()
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *AddOperatorParams) Run(_ ActionCtx) error {
	operator := &store.NamedKey{Name: p.name, KP: p.signerKP}
	s, err := store.CreateStore(p.name, GetConfig().StoreRoot, operator)
	if err != nil {
		return err
	}

	if p.token == "" {
		ctx, err := s.GetContext()
		if err != nil {
			return err
		}
		p.keyPath, err = ctx.KeyStore.Store(p.name, p.signerKP, "")
		if err != nil {
			return err
		}

		if p.Start != "" || p.Expiry != "" {
			oc, err := ctx.Store.ReadOperatorClaim()
			if err != nil {
				return err
			}
			if p.Start != "" {
				oc.NotBefore, err = p.TimeParams.StartDate()
				if err != nil {
					return err
				}
			}
			if p.Expiry != "" {
				oc.Expires, err = p.TimeParams.ExpiryDate()
				if err != nil {
					return err
				}
			}
			token, err := oc.Encode(p.signerKP)
			if err = s.StoreClaim([]byte(token)); err != nil {
				return err
			}
		}
	}

	if p.token != "" {
		if err := s.StoreClaim([]byte(p.token)); err != nil {
			return err
		}
	}

	GetConfig().Operator = operator.Name
	if err := GetConfig().Save(); err != nil {
		return err
	}

	return nil
}
