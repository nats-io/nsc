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

	"github.com/nats-io/nkeys"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cli"
	"github.com/spf13/cobra"
)

func deleteExportCmd() *cobra.Command {
	var params DeleteExportParams
	cmd := &cobra.Command{
		Use:          "export",
		Short:        "Delete an export",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}
			cmd.Printf("Success! - deleted export of %q\n", params.deletedExport.Subject)
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.accountName, "account", "a", "", "account storing the export")
	cmd.Flags().StringVarP(&params.subject, "subject", "s", "", "subject")

	return cmd
}

func init() {
	deleteCmd.AddCommand(deleteExportCmd())
}

type DeleteExportParams struct {
	accountName   string
	claim         *jwt.AccountClaims
	deletedExport *jwt.Export
	index         int
	SignerParams
	subject string
}

func (p *DeleteExportParams) SetDefaults(ctx ActionCtx) error {
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)
	p.index = -1
	if p.accountName == "" {
		p.accountName = ctx.StoreCtx().Account.Name
	}
	return nil
}

func (p *DeleteExportParams) PreInteractive(ctx ActionCtx) error {
	var err error
	p.accountName, err = ctx.StoreCtx().PickAccount(p.accountName)
	if err != nil {
		return err
	}
	return nil
}

func (p *DeleteExportParams) Load(ctx ActionCtx) error {
	var err error

	if p.accountName == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return errors.New("an account is required")
	}

	p.claim, err = ctx.StoreCtx().Store.ReadAccountClaim(p.accountName)
	if err != nil {
		return err
	}

	switch len(p.claim.Exports) {
	case 0:
		return fmt.Errorf("account %q doesn't have exports", p.accountName)
	default:
		for i, e := range p.claim.Exports {
			if string(e.Subject) == p.subject {
				p.index = i
				break
			}
		}
	}

	return nil
}

func (p *DeleteExportParams) PostInteractive(ctx ActionCtx) error {
	var err error

	var choices []string
	for _, c := range p.claim.Exports {
		choices = append(choices, fmt.Sprintf("[%s] %s - %s", c.Type, c.Name, c.Subject))
	}
	p.index, err = cli.PromptChoices("select export to delete", choices)
	if err != nil {
		return err
	}

	if err = p.SignerParams.Edit(ctx); err != nil {
		return err
	}

	return nil
}

func (p *DeleteExportParams) Validate(ctx ActionCtx) error {
	var err error
	if p.index == -1 {
		return fmt.Errorf("no matching export found")
	}
	if p.SignerParams.Resolve(ctx); err != nil {
		return err
	}
	return nil
}

func (p *DeleteExportParams) Run(ctx ActionCtx) error {
	p.deletedExport = p.claim.Exports[p.index]
	p.claim.Exports = append(p.claim.Exports[:p.index], p.claim.Exports[p.index+1:]...)

	token, err := p.claim.Encode(p.signerKP)
	if err != nil {
		return err
	}
	return ctx.StoreCtx().Store.StoreClaim([]byte(token))
}
