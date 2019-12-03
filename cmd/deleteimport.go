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
	"strings"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createDeleteImportCmd() *cobra.Command {
	var params DeleteImportParams
	cmd := &cobra.Command{
		Use:          "import",
		Short:        "Delete an import",
		Args:         MaxArgs(0),
		Example:      params.longHelp(),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().StringVarP(&params.subject, "subject", "s", "", "stream/service subject")
	cmd.Flags().StringVarP(&params.srcAccount, "src-account", "", "", "source account (only if subject is ambiguous)")
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	deleteCmd.AddCommand(createDeleteImportCmd())
}

type DeleteImportParams struct {
	AccountContextParams
	SignerParams
	claim      *jwt.AccountClaims
	index      int
	subject    string
	picked     bool
	srcAccount string
}

func (p *DeleteImportParams) longHelp() string {
	v := `toolName delete import -i
toolName delete import -s "bar.>"`
	return strings.Replace(v, "toolName", GetToolName(), -1)
}

func (p *DeleteImportParams) SetDefaults(ctx ActionCtx) error {
	if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
		return err
	}
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)
	p.index = -1

	return nil
}

func (p *DeleteImportParams) PreInteractive(ctx ActionCtx) error {
	p.picked = true
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

	// if auto-selecting there can only be one
	count := 0
	last := -1
	for i, e := range p.claim.Imports {
		if string(e.Subject) == p.subject {
			count++
			last = i
		}
	}
	if count == 1 {
		p.index = last
	}
	// if we have more than one, both the subject and src account must match
	if count > 1 {
		for i, e := range p.claim.Imports {
			if string(e.Subject) == p.subject && p.srcAccount == e.Account {
				p.index = i
				break
			}
		}
	}
	return nil
}

func (p *DeleteImportParams) PostInteractive(ctx ActionCtx) error {
	var err error

	choices, err := GetAccountImports(p.claim)
	if err != nil {
		return err
	}
	labels := choices.String()
	p.index, err = cli.Select("select import to delete", "", labels)
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

	if p.index == -1 && p.srcAccount == "" && !p.picked {
		var accounts []string
		for _, e := range p.claim.Imports {
			if string(e.Subject) == p.subject {
				accounts = append(accounts, e.Account)
			}
		}
		if len(accounts) > 1 && p.srcAccount == "" {
			return fmt.Errorf("more than one import %q found - specify --src-account with one of %s", p.subject, strings.Join(accounts, ", "))
		}
	}

	if p.index == -1 {
		m := fmt.Sprintf("no import matching %q found", p.subject)
		if p.srcAccount != "" {
			m = fmt.Sprintf("%s from account %s", m, p.srcAccount)
		}
		return fmt.Errorf(m)
	}

	if err = p.SignerParams.Resolve(ctx); err != nil {
		return err
	}
	return nil
}

func (p *DeleteImportParams) Run(ctx ActionCtx) (store.Status, error) {
	din := p.claim.Imports[p.index]
	p.claim.Imports = append(p.claim.Imports[:p.index], p.claim.Imports[p.index+1:]...)
	token, err := p.claim.Encode(p.signerKP)
	if err != nil {
		return nil, err
	}

	r := store.NewDetailedReport(true)
	r.AddOK("deleted %s import %q", din.Type, din.Subject)
	rs, err := ctx.StoreCtx().Store.StoreClaim([]byte(token))
	if rs != nil {
		r.Add(rs)
	}
	if err != nil {
		r.Add(store.FromError(err))
	}
	return r, nil
}
