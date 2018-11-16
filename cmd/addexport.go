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

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createExportCmd() *cobra.Command {
	var params AddExportParams
	cmd := &cobra.Command{
		Use:           "export",
		Short:         "Add an export",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := params.Init(); err != nil {
				return err
			}

			if params.export.Name == "" {
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

			cmd.Printf("Success! - added %s export %q\n", params.export.Type, params.export.Name)

			return nil
		},
	}
	cmd.Flags().StringVarP(&params.accountName, "account-name", "a", "", "account name")
	cmd.Flags().StringVarP(&params.export.Name, "name", "", "", "export name")
	cmd.Flags().StringVarP(&params.subject, "subject", "", "", "subject")
	cmd.Flags().BoolVarP(&params.service, "service", "", false, "export type service")

	return cmd
}

func init() {
	addCmd.AddCommand(createExportCmd())
}

type AddExportParams struct {
	claim       *jwt.AccountClaims
	export      jwt.Export
	subject     string
	accountName string
	operatorKP  nkeys.KeyPair
	stream      bool
	service     bool
}

func (p *AddExportParams) Init() error {
	s, err := getStore()
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

	p.export.Subject = jwt.Subject(p.subject)
	p.export.Type = jwt.StreamType
	if p.service {
		p.export.Type = jwt.ServiceType
	}

	return nil
}

func (p *AddExportParams) Interactive() error {
	s, err := getStore()
	if err != nil {
		return err
	}
	ctx, err := s.GetContext()
	if err != nil {
		return err
	}

	if p.accountName == "" {
		p.accountName = ctx.Account.Name
	}

	if p.accountName == "" {
		accounts, err := s.ListSubContainers(store.Accounts)
		if err != nil {
			return err
		}
		if len(accounts) > 1 {
			i, err := cli.PromptChoices("select account", accounts)
			if err != nil {
				return err
			}
			p.accountName = accounts[i]
		}
	}

	// allow downstream validation to have a surrogate account name
	if ctx.Account.Name == "" {
		ctx.Account.Name = p.accountName
	}

	p.export.Name, err = cli.Prompt("export name", p.export.Name, true, cli.LengthValidator(1))
	choices := []string{jwt.StreamType, jwt.ServiceType}
	i, err := cli.PromptChoices("export type", choices)
	if err != nil {
		return err
	}
	p.export.Type = choices[i]
	p.subject, err = cli.Prompt("subject", p.subject, true, func(s string) error {
		p.export.Subject = jwt.Subject(s)
		var vr jwt.ValidationResults
		p.export.Validate(&vr)
		if len(vr.Issues) > 0 {
			return errors.New(vr.Issues[0].Description)
		}
		return nil
	})

	p.operatorKP, err = ctx.ResolveKey(nkeys.PrefixByteOperator, KeyPathFlag)
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

func (p *AddExportParams) Validate() error {
	s, err := getStore()
	if err != nil {
		return err
	}

	if p.accountName == "" {
		return errors.New("an account is required")
	}
	p.claim, err = s.ReadAccountClaim(p.accountName)
	if err != nil {
		return err
	}

	// get the old validation results
	var vr jwt.ValidationResults
	if err = p.claim.Exports.Validate(&vr); err != nil {
		return err
	}

	// add the new claim
	p.claim.Exports.Add(&p.export)
	var vr2 jwt.ValidationResults
	if err = p.claim.Exports.Validate(&vr2); err != nil {
		return err
	}

	// filter out all the old validations
	uvr := jwt.CreateValidationResults()
	if len(vr.Issues) > 0 {
		for _, nis := range vr.Issues {
			for _, is := range vr2.Issues {
				if nis.Description == is.Description {
					continue
				}
			}
			uvr.Add(nis)
		}
	} else {
		uvr = &vr2
	}
	// fail validation
	if len(uvr.Issues) > 0 {
		return errors.New(uvr.Issues[0].Error())
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

func (p *AddExportParams) Run() error {
	s, err := getStore()
	if err != nil {
		return nil
	}
	token, err := p.claim.Encode(p.operatorKP)
	return s.StoreClaim([]byte(token))
}
