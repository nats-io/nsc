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

func createGenerateActivationCmd() *cobra.Command {
	var params GenerateActivationParams
	cmd := &cobra.Command{
		Use:          "activation",
		Short:        "Generate an export activation jwt token",
		Args:         cobra.MaximumNArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}

			if err := Write(params.out, FormatJwt("Activation", params.Token)); err != nil {
				return err
			}

			if QuietMode() {
				cmd.Printf("Success! - generated %q activation for account %q.\nJTI is %q\n",
					params.export.Name, params.targetPK, params.activation.ID)
			} else {
				cmd.Printf("generated %q activation for account %q.\nJTI is %q\n",
					params.export.Name, params.targetPK, params.activation.ID)
			}

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

			return nil
		},
	}
	cmd.Flags().StringVarP(&params.subject, "subject", "s", "", "export subject")
	cmd.Flags().StringVarP(&params.out, "output-file", "o", "--", "output file '--' is stdout")
	params.targetKey.BindFlags("target-account", "t", nkeys.PrefixByteAccount, false, cmd)
	params.timeParams.BindFlags(cmd)
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	generateCmd.AddCommand(createGenerateActivationCmd())
}

type GenerateActivationParams struct {
	AccountContextParams
	activation     *jwt.ActivationClaims
	claims         *jwt.AccountClaims
	export         jwt.Export
	out            string
	privateExports jwt.Exports
	SignerParams
	subject    string
	targetKey  NKeyParams
	targetPK   string
	timeParams TimeParams
	Token      string
}

func (p *GenerateActivationParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.SetDefaults(ctx)
	p.SignerParams.SetDefaults(nkeys.PrefixByteAccount, false, ctx)
	p.export.Subject = jwt.Subject(p.subject)

	return nil
}

func (p *GenerateActivationParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}
	return nil
}

func (p *GenerateActivationParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	p.claims, err = ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		return err
	}

	if len(p.claims.Exports) == 0 {
		return fmt.Errorf("account %q doesn't have exports", p.AccountContextParams.Name)
	}

	for _, v := range p.claims.Exports {
		if v.TokenReq {
			p.privateExports.Add(v)
		}
	}

	if len(p.privateExports) == 0 {
		return fmt.Errorf("account %q doesn't have exports that require token generation", p.AccountContextParams.Name)
	}

	return nil
}

func (p *GenerateActivationParams) PostInteractive(ctx ActionCtx) error {
	var err error

	if p.subject == "" && len(p.privateExports) == 1 {
		p.subject = string(p.privateExports[0].Subject)
	}

	var choices []string
	if p.export.Subject == "" {
		for _, v := range p.privateExports {
			choices = append(choices, fmt.Sprintf("[%s] %s - %s", v.Type, v.Name, v.Subject))
		}
	}
	i, err := cli.PromptChoices("select export", choices)
	if err != nil {
		return err
	}
	p.export = *p.privateExports[i]
	p.subject = string(p.export.Subject)

	if err = p.targetKey.Edit(); err != nil {
		return err
	}

	if err := p.timeParams.Edit(); err != nil {
		return err
	}

	if err = p.SignerParams.Edit(ctx); err != nil {
		return err
	}

	return nil
}

func (p *GenerateActivationParams) Validate(ctx ActionCtx) error {
	var err error

	if len(p.privateExports) == 1 {
		p.subject = string(p.privateExports[0].Subject)
	}

	if p.subject == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return errors.New("a subject is required")
	}

	if err = p.timeParams.Validate(); err != nil {
		return err
	}

	if p.targetPK, err = p.targetKey.PublicKey(); err != nil {
		return err
	}

	sub := jwt.Subject(p.subject)
	for _, e := range p.privateExports {
		if sub.IsContainedIn(e.Subject) {
			p.export = *e
			break
		}
	}

	if p.export.Subject == "" {
		return fmt.Errorf("an export containing %q was not found in account %q", p.subject, p.AccountContextParams.Name)
	}

	if err = p.SignerParams.Resolve(ctx); err != nil {
		return err
	}
	return nil
}

func (p *GenerateActivationParams) Run(ctx ActionCtx) error {
	var err error
	p.activation = jwt.NewActivationClaims(p.targetPK)
	p.activation.NotBefore, _ = p.timeParams.StartDate()
	p.activation.Expires, _ = p.timeParams.ExpiryDate()
	p.activation.Activation.ImportSubject = p.export.Subject
	p.activation.Activation.ImportType = p.export.Type

	p.Token, err = p.activation.Encode(p.signerKP)
	if err != nil {
		return err
	}

	return nil
}
