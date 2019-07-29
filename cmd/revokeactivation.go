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
	"strconv"
	"time"

	"github.com/spf13/cobra"
)

func createRevokeActivationCmd() *cobra.Command {
	var params RevokeActivationParams
	cmd := &cobra.Command{
		Use:          "activation",
		Short:        "Revoke an accounts access to an export",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}

			if !QuietMode() {
				cmd.Printf("Revoked account %s from export %s\n", params.accountKey.publicKey, params.export.Subject)
			}
			return nil
		},
	}

	cmd.Flags().IntVarP(&params.at, "at", "", 0, "revokes all user credentials created before a Unix timestamp ('0' is treated as now)")
	cmd.Flags().StringVarP(&params.subject, "subject", "s", "", "export subject")
	cmd.Flags().BoolVarP(&params.service, "service", "", false, "service")
	params.accountKey.BindFlags("target-account", "t", nkeys.PrefixByteAccount, cmd)

	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	revokeCmd.AddCommand(createRevokeActivationCmd())
}

// RevokeActivationParams hold the info necessary to add a user to the revocation list in an account
type RevokeActivationParams struct {
	AccountContextParams
	SignerParams
	claim           *jwt.AccountClaims
	export          *jwt.Export
	possibleExports jwt.Exports
	at              int
	subject         string
	service         bool
	accountKey      PubKeyParams
}

func (p *RevokeActivationParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.SetDefaults(ctx)
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)
	return nil
}

func (p *RevokeActivationParams) canParse(s string) error {
	_, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("%s is invalid: %v", s, err)
	}
	return nil
}

func (p *RevokeActivationParams) PreInteractive(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}

	p.service, err = cli.PromptBoolean("is service", p.service)
	if err != nil {
		return err
	}

	return nil
}

func (p *RevokeActivationParams) Load(ctx ActionCtx) error {
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
		return fmt.Errorf("account %q doesn't have %s exports that qualify",
			p.AccountContextParams.Name, kind.String())
	}

	return nil
}

func (p *RevokeActivationParams) Validate(ctx ActionCtx) error {

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

	if err := p.SignerParams.Resolve(ctx); err != nil {
		return err
	}

	return nil
}

func (p *RevokeActivationParams) PostInteractive(ctx ActionCtx) error {
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

	i, err := cli.PromptChoices(fmt.Sprintf("select %s export", kind.String()), "", choices)
	if err != nil {
		return err
	}
	p.export = p.possibleExports[i]
	if p.subject == "" {
		p.subject = string(p.export.Subject)
	}

	if err = p.accountKey.Edit(); err != nil {
		return err
	}

	if p.at == 0 {
		at := fmt.Sprintf("%d", p.at)
		at, err = cli.Prompt("revoke all credentials created before (0 is now)", at, true, p.canParse)
		p.at, err = strconv.Atoi(at)
	}

	if err := p.SignerParams.Edit(ctx); err != nil {
		return err
	}

	return nil
}

func (p *RevokeActivationParams) Run(ctx ActionCtx) error {
	if p.export == nil {
		return fmt.Errorf("unable to locate export")
	}

	if p.at == 0 {
		p.export.Revoke(p.accountKey.publicKey)
	} else {
		p.export.RevokeAt(p.accountKey.publicKey, time.Unix(int64(p.at), 0))
	}

	token, err := p.claim.Encode(p.signerKP)
	if err != nil {
		return err
	}
	return ctx.StoreCtx().Store.StoreClaim([]byte(token))
}
