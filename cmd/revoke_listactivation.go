// Copyright 2018-2025 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"time"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
	"github.com/xlab/tablewriter"
)

func createRevokeListActivationCmd() *cobra.Command {
	var params RevokeListActivationParams
	cmd := &cobra.Command{
		Use:          "list_activations",
		Aliases:      []string{"list-activations"},
		Short:        "List account revocations for an export",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}

	cmd.Flags().StringVarP(&params.subject, "subject", "s", "", "export subject")
	cmd.Flags().BoolVarP(&params.service, "service", "", false, "service")

	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	revokeCmd.AddCommand(createRevokeListActivationCmd())
}

// RevokeListActivationParams hold the info necessary to add a user to the revocation list in an account
type RevokeListActivationParams struct {
	AccountContextParams
	SignerParams
	claim           *jwt.AccountClaims
	export          *jwt.Export
	possibleExports jwt.Exports
	subject         string
	service         bool
}

func (p *RevokeListActivationParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.SetDefaults(ctx)
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)
	return nil
}

func (p *RevokeListActivationParams) PreInteractive(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}

	p.service, err = cli.Confirm("is service", p.service)
	if err != nil {
		return err
	}

	return nil
}

func (p *RevokeListActivationParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	p.claim, err = ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		return err
	}

	if len(p.claim.Exports) == 0 {
		return fmt.Errorf("account %q doesn't have exports", p.AccountContextParams.Name)
	}

	kind := jwt.Stream
	if p.service {
		kind = jwt.Service
	}

	for _, v := range p.claim.Exports {
		if v.Type != kind {
			continue
		}
		p.possibleExports.Add(v)
	}

	if len(p.possibleExports) == 0 {
		return fmt.Errorf("account %q doesn't have %v exports",
			p.AccountContextParams.Name, kind)
	}

	return nil
}

func (p *RevokeListActivationParams) Validate(ctx ActionCtx) error {

	if len(p.possibleExports) == 1 && p.subject == "" {
		p.subject = string(p.possibleExports[0].Subject)
	}

	if p.subject == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return fmt.Errorf("a subject is required")
	}

	sub := jwt.Subject(p.subject)
	for _, e := range p.possibleExports {
		if sub.IsContainedIn(e.Subject) {
			p.export = e
			break
		}
	}

	if err := p.SignerParams.Resolve(ctx); err != nil {
		return err
	}

	return nil
}

func (p *RevokeListActivationParams) PostInteractive(ctx ActionCtx) error {
	var choices []string
	if p.subject == "" {
		for _, v := range p.possibleExports {
			choices = append(choices, string(v.Subject))
		}
	}
	kind := jwt.Stream
	if p.service {
		kind = jwt.Service
	}

	i, err := cli.Select(fmt.Sprintf("select %s export", kind.String()), "", choices)
	if err != nil {
		return err
	}
	p.export = p.possibleExports[i]
	if p.subject == "" {
		p.subject = string(p.export.Subject)
	}

	if err := p.SignerParams.Edit(ctx); err != nil {
		return err
	}

	return nil
}

func (p *RevokeListActivationParams) Run(ctx ActionCtx) (store.Status, error) {
	if p.export == nil {
		return nil, fmt.Errorf("unable to locate export")
	}
	kind := jwt.Stream
	if p.service {
		kind = jwt.Service
	}
	if len(p.export.Revocations) == 0 {
		return nil, fmt.Errorf("%v %s has no revocations", kind, p.export.Name)
	}

	name := p.export.Name
	if name == "" {
		name = string(p.export.Subject)
	}

	table := tablewriter.CreateTable()
	table.AddTitle(fmt.Sprintf("Revoked Accounts for %v %s", kind, name))
	table.AddHeaders("Public Key", "Revoke Credentials Before")

	for pubKey, at := range p.export.Revocations {
		if pubKey == "*" {
			pubKey = "* [All Accounts]"
		}
		t := time.Unix(at, 0)
		formatted := t.Format(time.RFC1123)
		table.AddRow(pubKey, formatted)
	}

	_, err := fmt.Fprintln(ctx.CurrentCmd().OutOrStdout(), table.Render())
	return nil, err
}
