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
	"fmt"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createDeleteExportCmd() *cobra.Command {
	var params DeleteExportParams
	cmd := &cobra.Command{
		Use:          "export",
		Short:        "Delete an export",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().StringVarP(&params.subject, "subject", "s", "", "subject")
	params.AccountContextParams.BindFlags(cmd)
	return cmd
}

func init() {
	deleteCmd.AddCommand(createDeleteExportCmd())
}

type DeleteExportParams struct {
	AccountContextParams
	SignerParams
	claim   *jwt.AccountClaims
	index   int
	subject string
}

func (p *DeleteExportParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.SetDefaults(ctx)
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)
	p.index = -1
	return nil
}

func (p *DeleteExportParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}
	return nil
}

func (p *DeleteExportParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	p.claim, err = ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		return err
	}

	switch len(p.claim.Exports) {
	case 0:
		return fmt.Errorf("account %q doesn't have exports", p.AccountContextParams.Name)
	case 1:
		if p.subject == "" {
			p.subject = string(p.claim.Exports[0].Subject)
		}
	}
	for i, e := range p.claim.Exports {
		if string(e.Subject) == p.subject {
			p.index = i
			break
		}
	}

	return nil
}

func (p *DeleteExportParams) PostInteractive(ctx ActionCtx) error {
	var err error

	choices, err := GetAccountExports(p.claim)
	if err != nil {
		return err
	}
	labels := AccountExportChoices(choices).String()

	p.index, err = cli.Select("select export to delete", "", labels)
	if err != nil {
		return err
	}

	if err = p.SignerParams.Edit(ctx); err != nil {
		return err
	}

	return nil
}

func (p *DeleteExportParams) Validate(ctx ActionCtx) error {
	if p.subject == "" && p.index == -1 {
		return fmt.Errorf("subject is required")
	}
	if p.index == -1 {
		return fmt.Errorf("no export matching %q found", p.subject)
	}
	if err := p.SignerParams.Resolve(ctx); err != nil {
		return err
	}
	return nil
}

func (p *DeleteExportParams) Run(ctx ActionCtx) (store.Status, error) {
	dex := p.claim.Exports[p.index]
	p.claim.Exports = append(p.claim.Exports[:p.index], p.claim.Exports[p.index+1:]...)
	token, err := p.claim.Encode(p.signerKP)
	if err != nil {
		return nil, err
	}

	r := store.NewDetailedReport(true)
	r.AddOK("deleted %s export %q", dex.Type, dex.Subject)
	rs, err := ctx.StoreCtx().Store.StoreClaim([]byte(token))
	if rs != nil {
		r.Add(rs)
	}
	if err != nil {
		r.AddFromError(err)
	}
	return r, nil
}
