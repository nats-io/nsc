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
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createGenerateExport() *cobra.Command {
	var params GenerateActivationParams
	cmd := &cobra.Command{
		Use:           "activation",
		Short:         "Generate an export activation jwt token",
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
			if err := Write(params.out, FormatJwt("Activation", params.token)); err != nil {
				return err
			}

			cmd.Printf("Success! - generated %q activation for account %q.\nJTI is %q\n",
				params.export.Name, params.targetAccount, params.activation.ID)

			if params.activation.NotBefore > 0 {
				cmd.Printf("Token valid on %s - %s\n",
					UnixToDate(params.activation.NotBefore),
					HumanizedDate(params.activation.NotBefore))
			}
			if params.activation.Expires > 0 {
				cmd.Printf("Token expires on %s - %s\n",
					UnixToDate(params.activation.Expires),
					HumanizedDate(params.activation.Expires))
			}

			return RunInterceptor(cmd)
		},
	}
	cmd.Flags().StringVarP(&params.accountName, "account-name", "a", "", "account name")
	cmd.Flags().StringVarP(&params.targetAccount, "target-account", "t", "", "account public key")
	cmd.Flags().StringVarP(&params.subject, "subject", "s", "", "export subject")
	cmd.Flags().StringVarP(&params.out, "output-file", "o", "--", "output file '--' is stdout")
	params.BindFlags(cmd)

	return cmd
}

func init() {
	generateCmd.AddCommand(createGenerateExport())
}

type GenerateActivationParams struct {
	TimeParams
	accountKP     nkeys.KeyPair
	accountName   string
	claims        *jwt.AccountClaims
	export        jwt.Export
	out           string
	subject       string
	targetAccount string
	token         string
	activation    *jwt.ActivationClaims
}

func (p *GenerateActivationParams) Init() error {
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

	p.export.Subject = jwt.Subject(p.subject)

	return nil
}

func (p *GenerateActivationParams) Interactive() error {
	s, err := GetStore()
	if err != nil {
		return err
	}
	if p.accountName == "" {
		accounts, err := s.ListSubContainers(store.Accounts)
		if err != nil {
			return err
		}
		if len(accounts) > 1 {
			i, err := cli.PromptChoices("user account", accounts)
			if err != nil {
				return err
			}
			p.accountName = accounts[i]
		}
	}

	if p.targetAccount == "" {
		p.targetAccount, err = cli.Prompt("target account nkey", p.targetAccount, true, func(s string) error {
			if !nkeys.IsValidPublicAccountKey([]byte(s)) {
				return errors.New("not a valid account nkey")
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	p.claims, err = s.ReadAccountClaim(p.accountName)
	if err != nil {
		return err
	}

	if len(p.claims.Exports) == 0 {
		return fmt.Errorf("account %q doesn't have exports", p.accountName)
	}

	sub := jwt.Subject(p.subject)
	for _, e := range p.claims.Exports {
		if sub.IsContainedIn(e.Subject) {
			p.export = *e
			break
		}
	}

	var choices []string
	if p.export.Subject == "" {
		for _, v := range p.claims.Exports {
			choices = append(choices, fmt.Sprintf("[%s] %s - %s", v.Type, v.Name, v.Subject))
		}
	}
	i, err := cli.PromptChoices("select export", choices)
	if err != nil {
		return err
	}
	p.export = *p.claims.Exports[i]

	if err := p.TimeParams.Edit(); err != nil {
		return err
	}

	return nil
}

func (p *GenerateActivationParams) Validate(cmd *cobra.Command) error {
	s, err := GetStore()
	if err != nil {
		return err
	}

	if p.export.Subject == "" {
		cmd.SilenceUsage = false
		return fmt.Errorf("subject not specified")
	}

	if err := p.TimeParams.Validate(); err != nil {
		return err
	}

	if p.accountName == "" {
		// default account was not found by get context, so we either we have none or many
		accounts, err := s.ListSubContainers(store.Accounts)
		if err != nil {
			return err
		}
		c := len(accounts)
		if c == 0 {
			return errors.New("no accounts defined - add account first")
		} else {
			return errors.New("multiple accounts found - specify --account-name or navigate to an account directory")
		}
	}

	if p.targetAccount == "" {
		cmd.SilenceUsage = false
		return fmt.Errorf("target account cannot be empty")
	}

	if !nkeys.IsValidPublicAccountKey([]byte(p.targetAccount)) {
		return fmt.Errorf("invalid target account public key")
	}

	p.claims, err = s.ReadAccountClaim(p.accountName)
	if err != nil {
		return err
	}

	sub := jwt.Subject(p.subject)
	for _, e := range p.claims.Exports {
		if sub.IsContainedIn(e.Subject) {
			p.export = *e
			break
		}
	}

	if p.export.Subject == "" {
		return fmt.Errorf("an export containing %q was not found in account %q", p.subject, p.accountName)
	}

	ctx, err := s.GetContext()
	if err != nil {
		return err
	}

	if ctx.Account.Name == "" {
		ctx.Account.Name = p.accountName
	}

	p.accountKP, err = ctx.ResolveKey(nkeys.PrefixByteAccount, KeyPathFlag)
	if err != nil {
		return fmt.Errorf("specify the account private key with --private-key to use for signing the activation")
	}

	return nil
}

func (p *GenerateActivationParams) Run() error {
	var err error
	p.activation = jwt.NewActivationClaims(p.targetAccount)
	p.activation.NotBefore, _ = p.TimeParams.StartDate()
	p.activation.Expires, _ = p.TimeParams.ExpiryDate()
	p.activation.Exports.Add(&p.export)

	p.token, err = p.activation.Encode(p.accountKP)
	if err != nil {
		return err
	}

	return nil
}
