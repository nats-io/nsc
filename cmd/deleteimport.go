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

func deleteImportCmd() *cobra.Command {
	var params DeleteImportParams
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Delete an import",
		Example: `nsc delete import -i
nsc delete import -s "bar.>"`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}
			cmd.Printf("Success! - deleted import of %q\n", params.deletedImport.Subject)
			return nil
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
	accountName   string
	claim         *jwt.AccountClaims
	deletedImport *jwt.Import
	index         int
	SignerParams
	subject string
}

func (p *DeleteImportParams) SetDefaults(ctx ActionCtx) error {
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)
	p.index = -1
	if p.accountName == "" {
		p.accountName = ctx.StoreCtx().Account.Name
	}
	return nil
}

func (p *DeleteImportParams) PreInteractive(ctx ActionCtx) error {
	var err error
	p.accountName, err = ctx.StoreCtx().PickAccount(p.accountName)
	if err != nil {
		return err
	}
	return nil
}

func (p *DeleteImportParams) Load(ctx ActionCtx) error {
	var err error

	if p.accountName == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return errors.New("an account is required")
	}

	p.claim, err = ctx.StoreCtx().Store.ReadAccountClaim(p.accountName)
	if err != nil {
		return err
	}

	switch len(p.claim.Imports) {
	case 0:
		return fmt.Errorf("account %q doesn't have imports", p.accountName)
	default:
		for i, e := range p.claim.Imports {
			if string(e.Subject) == p.subject {
				p.index = i
				break
			}
		}
	}

	return nil
}

func (p *DeleteImportParams) PostInteractive(ctx ActionCtx) error {
	var err error

	var choices []string
	for _, c := range p.claim.Exports {
		choices = append(choices, fmt.Sprintf("[%s] %s - %s", c.Type, c.Name, c.Subject))
	}
	p.index, err = cli.PromptChoices("select import to delete", choices)
	if err != nil {
		return err
	}

	if err = p.SignerParams.Edit(ctx); err != nil {
		return err
	}

	return nil
}

func (p *DeleteImportParams) Validate(ctx ActionCtx) error {
	var err error
	if p.index == -1 {
		return fmt.Errorf("no matching import found")
	}
	if err = p.SignerParams.Resolve(ctx); err != nil {
		return err
	}
	return nil
}

func (p *DeleteImportParams) Run(ctx ActionCtx) error {
	p.deletedImport = p.claim.Imports[p.index]
	p.claim.Imports = append(p.claim.Imports[:p.index], p.claim.Imports[p.index+1:]...)

	token, err := p.claim.Encode(p.signerKP)
	if err != nil {
		return err
	}
	return ctx.StoreCtx().Store.StoreClaim([]byte(token))
}
