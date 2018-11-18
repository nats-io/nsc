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

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
	"github.com/spf13/cobra"
)

// TODO: convert to Action
func deleteImportCmd() *cobra.Command {
	var params DeleteImportParams
	cmd := &cobra.Command{
		Use:           "import",
		Short:         "Delete an import",
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

			if err := params.Validate(cmd); err != nil {
				return err
			}

			if err := params.Run(); err != nil {
				return err
			}

			cmd.Printf("Success! - deleted import of %q\n", params.deletedImport.Subject)

			return RunInterceptor(cmd)
		},
	}
	cmd.Flags().StringVarP(&params.accountName, "account-name", "a", "", "account name")
	cmd.Flags().StringVarP(&params.subject, "subject", "s", "", "subject")

	return cmd
}

func init() {
	deleteCmd.AddCommand(deleteImportCmd())
}

type DeleteImportParams struct {
	deletedImport *jwt.Import
	claim         *jwt.AccountClaims
	index         int
	subject       string
	accountName   string
	operatorKP    nkeys.KeyPair
}

func (p *DeleteImportParams) Init() error {
	p.index = -1

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

	return nil
}

func (p *DeleteImportParams) Interactive() error {
	s, err := GetStore()
	if err != nil {
		return err
	}
	ctx, err := s.GetContext()
	if err != nil {
		return err
	}

	p.accountName, err = ctx.PickAccount(p.accountName)
	if err != nil {
		return err
	}

	p.claim, err = s.ReadAccountClaim(p.accountName)
	if err != nil {
		return err
	}

	if len(p.claim.Imports) == 0 {
		return fmt.Errorf("account %q doesn't have imports", p.accountName)
	}

	var choices []string
	for _, c := range p.claim.Imports {
		choices = append(choices, fmt.Sprintf("[%s] %s - %s", c.Type, c.Name, c.Subject))
	}
	p.index, err = cli.PromptChoices("select import to delete", choices)
	if err != nil {
		return err
	}

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

func (p *DeleteImportParams) Validate(cmd *cobra.Command) error {
	s, err := GetStore()
	if err != nil {
		return err
	}

	if p.accountName == "" {
		cmd.SilenceUsage = false
		return errors.New("an account is required")
	}

	if p.claim == nil {
		p.claim, err = s.ReadAccountClaim(p.accountName)
		if err != nil {
			return err
		}
	}

	if !InteractiveFlag {
		switch len(p.claim.Imports) {
		case 0:
			return fmt.Errorf("account %q doesn't have imports", p.accountName)
		case 1:
			p.index = 0
		default:
			for i, v := range p.claim.Imports {
				if string(v.Subject) == p.subject {
					p.index = i
					break
				}
			}
		}
	}

	if p.index == -1 {
		return fmt.Errorf("no matching imports found")
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

func (p *DeleteImportParams) Run() error {
	s, err := GetStore()
	if err != nil {
		return nil
	}

	p.deletedImport = p.claim.Imports[p.index]
	p.claim.Imports = append(p.claim.Imports[:p.index], p.claim.Imports[p.index+1:]...)

	token, err := p.claim.Encode(p.operatorKP)
	return s.StoreClaim([]byte(token))
}
