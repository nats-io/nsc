/*
 * Copyright 2018-2020 The NATS Authors
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
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createClearRevokeActivationCmd() *cobra.Command {
	var params RevokeClearActivationParams
	cmd := &cobra.Command{
		Use:          "delete_activation",
		Aliases:      []string{"delete-activation"},
		Short:        "Remove an account revocation from an export",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}

	cmd.Flags().StringVarP(&params.subject, "subject", "s", "", "export subject")
	cmd.Flags().BoolVarP(&params.service, "service", "", false, "service")
	params.accountKey.BindFlags("target-account", "t", nkeys.PrefixByteAccount, cmd)

	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	revokeCmd.AddCommand(createClearRevokeActivationCmd())
}

// RevokeClearActivationParams hold the info necessary to add a user to the revocation list in an account
type RevokeClearActivationParams struct {
	AccountContextParams
	SignerParams
	claim           *jwt.AccountClaims
	export          *jwt.Export
	possibleExports jwt.Exports
	subject         string
	service         bool
	accountKey      PubKeyParams
}

func (p *RevokeClearActivationParams) SetDefaults(ctx ActionCtx) error {
	p.accountKey.AllowWildcard = true
	p.AccountContextParams.SetDefaults(ctx)
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)
	return nil
}

func (p *RevokeClearActivationParams) PreInteractive(ctx ActionCtx) error {
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

func (p *RevokeClearActivationParams) Load(ctx ActionCtx) error {
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

func (p *RevokeClearActivationParams) PostInteractive(ctx ActionCtx) error {
	var exports []string
	if p.subject == "" {
		for _, v := range p.possibleExports {
			exports = append(exports, string(v.Subject))
		}
	}
	kind := jwt.Stream
	if p.service {
		kind = jwt.Service
	}

	i, err := cli.Select(fmt.Sprintf("select %v export", kind), "", exports)
	if err != nil {
		return err
	}
	p.export = p.possibleExports[i]
	if p.subject == "" {
		p.subject = string(p.export.Subject)
	}
	if len(p.export.Revocations) == 0 {
		return fmt.Errorf("%v export %s doesn't have revocations", kind, p.export.Name)
	}
	accounts, err := ListAccounts(ctx.StoreCtx().Store)
	if err != nil {
		return err
	}
	keyToName := make(map[string]string)
	keyToName["*"] = "* [All Accounts]"
	for _, a := range accounts {
		if a.Err == nil {
			keyToName[a.Claims.Claims().Subject] = a.Name
		}
	}
	var keys []PubKeyChoice
	for k := range p.export.Revocations {
		n := keyToName[k]
		if n == "" {
			n = "[Unknown Account]"
		}
		n = fmt.Sprintf("%s: %s", k, n)
		keys = append(keys, PubKeyChoice{Key: k, Label: n})
	}
	if err = p.accountKey.Select("select account revocation to delete", keys...); err != nil {
		return err
	}
	return p.SignerParams.Edit(ctx)
}

func (p *RevokeClearActivationParams) Validate(ctx ActionCtx) error {
	if len(p.possibleExports) == 1 && p.subject == "" {
		p.subject = string(p.possibleExports[0].Subject)
	}
	if p.subject == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return fmt.Errorf("a subject is required")
	}
	if err := p.accountKey.Valid(); err != nil {
		return err
	}
	sub := jwt.Subject(p.subject)
	for _, e := range p.possibleExports {
		if sub.IsContainedIn(e.Subject) {
			p.export = e
			break
		}
	}
	if p.export == nil {
		return fmt.Errorf("unable to locate export")
	}
	return p.SignerParams.Resolve(ctx)
}

func (p *RevokeClearActivationParams) Run(ctx ActionCtx) (store.Status, error) {
	p.export.ClearRevocation(p.accountKey.publicKey)
	token, err := p.claim.Encode(p.signerKP)
	if err != nil {
		return nil, err
	}
	r := store.NewDetailedReport(true)
	StoreAccountAndUpdateStatus(ctx, token, r)
	if r.HasNoErrors() {
		kind := jwt.Stream
		if p.service {
			kind = jwt.Service
		}

		if p.accountKey.publicKey == jwt.All {
			r.AddOK("deleted %v %s revocation for all accounts", kind, p.export.Name)
		} else {
			r.AddOK("deleted %v %s revocation for account %s", kind, p.export.Name, p.accountKey.publicKey)
		}
	}
	return r, nil
}
