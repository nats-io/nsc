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
	"fmt"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
	"github.com/spf13/cobra"
)

func createDeleteImportCmd() *cobra.Command {
	var params DeleteImportParams
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Delete an import",
		Args:  cobra.MaximumNArgs(0),
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
	cmd.Flags().StringVarP(&params.subject, "subject", "s", "", "subject")
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	deleteCmd.AddCommand(createDeleteImportCmd())
}

type DeleteImportParams struct {
	AccountContextParams
	claim         *jwt.AccountClaims
	deletedImport *jwt.Import
	index         int
	SignerParams
	subject string
}

func (p *DeleteImportParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.SetDefaults(ctx)
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)
	p.index = -1

	return nil
}

func (p *DeleteImportParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}
	return nil
}

func (p *DeleteImportParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	p.claim, err = ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		return err
	}

	switch len(p.claim.Imports) {
	case 0:
		return fmt.Errorf("account %q doesn't have imports", p.AccountContextParams.Name)
	case 1:
		if p.subject == "" {
			p.subject = string(p.claim.Imports[0].Subject)
		}
	}

	for i, e := range p.claim.Imports {
		if string(e.Subject) == p.subject {
			p.index = i
			break
		}
	}

	return nil
}

func (p *DeleteImportParams) PostInteractive(ctx ActionCtx) error {
	var err error

	var choices []string
	for _, c := range p.claim.Imports {
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
	if p.subject == "" && p.index == -1 {
		return fmt.Errorf("subject is required")
	}
	if p.index == -1 {
		return fmt.Errorf("no import matching %q found", p.subject)
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
