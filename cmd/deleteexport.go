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

func deleteExportCmd() *cobra.Command {
	var params DeleteExportParams
	cmd := &cobra.Command{
		Use:           "export",
		Short:         "Delete an export",
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

			cmd.Printf("Success! - deleted export of %q\n", params.deletedExport.Subject)

			return RunInterceptor(cmd)
		},
	}
	cmd.Flags().StringVarP(&params.accountName, "account-name", "a", "", "account name")
	cmd.Flags().StringVarP(&params.subject, "subject", "s", "", "subject")

	return cmd
}

func init() {
	deleteCmd.AddCommand(deleteExportCmd())
}

type DeleteExportParams struct {
	deletedExport *jwt.Export
	claim         *jwt.AccountClaims
	index         int
	subject       string
	accountName   string
	operatorKP    nkeys.KeyPair
}

func (p *DeleteExportParams) Init() error {
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

func (p *DeleteExportParams) Interactive() error {
	s, err := GetStore()
	if err != nil {
		return err
	}
	ctx, err := s.GetContext()
	if err != nil {
		return err
	}

	p.accountName, err = PickAccount(ctx, p.accountName)
	if err != nil {
		return err
	}

	p.claim, err = s.ReadAccountClaim(p.accountName)
	if err != nil {
		return err
	}

	if len(p.claim.Exports) == 0 {
		return fmt.Errorf("account %q doesn't have exports", p.accountName)
	}

	var choices []string
	for _, c := range p.claim.Exports {
		choices = append(choices, fmt.Sprintf("[%s] %s - %s", c.Type, c.Name, c.Subject))
	}
	p.index, err = cli.PromptChoices("select export to delete", choices)
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

func (p *DeleteExportParams) Validate(cmd *cobra.Command) error {
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
		switch len(p.claim.Exports) {
		case 0:
			return fmt.Errorf("account %q doesn't have exports", p.accountName)
		case 1:
			p.index = 0
		default:
			for i, e := range p.claim.Exports {
				if string(e.Subject) == p.subject {
					p.index = i
					break
				}
			}
		}
	}

	if p.index == -1 {
		return fmt.Errorf("no matching exports found")
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

func (p *DeleteExportParams) Run() error {
	s, err := GetStore()
	if err != nil {
		return nil
	}

	p.deletedExport = p.claim.Exports[p.index]
	p.claim.Exports = append(p.claim.Exports[:p.index], p.claim.Exports[p.index+1:]...)

	token, err := p.claim.Encode(p.operatorKP)
	return s.StoreClaim([]byte(token))
}
