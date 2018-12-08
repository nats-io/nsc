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
	"sort"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/spf13/cobra"
)

func createEditAccount() *cobra.Command {
	var params EditAccountParams
	cmd := &cobra.Command{
		Use:          "account",
		Short:        "Edit an account",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}

			if !QuietMode() {
				cmd.Printf("Success! - edited account %q\n", params.AccountContextParams.Name)

				_ = Write("--", FormatJwt("Account", params.token))

				if params.claim.NotBefore > 0 {
					cmd.Printf("Token valid on %s - %s\n",
						UnixToDate(params.claim.NotBefore),
						HumanizedDate(params.claim.NotBefore))
				}
				if params.claim.Expires > 0 {
					cmd.Printf("Token expires on %s - %s\n",
						UnixToDate(params.claim.Expires),
						HumanizedDate(params.claim.Expires))
				}
				if params.claim.Limits.Conn > 0 {
					cmd.Printf("Maximum active connections set to %d\n",
						params.claim.Limits.Conn)
				}
			}

			return nil
		},
	}
	cmd.Flags().StringSliceVarP(&params.tags, "tag", "", nil, "add tags for user - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.rmTags, "rm-tag", "", nil, "remove tag - comma separated list or option can be specified multiple times")
	cmd.Flags().Int64VarP(&params.conns.NumberValue, "conns", "", -1, "set maximum active connections for the account (-1 is unlimited)")
	cmd.Flags().StringVarP(&params.data.Value, "data", "", "-1", "set maximum data in bytes for the account (-1 is unlimited)")
	cmd.Flags().Int64VarP(&params.exports.NumberValue, "exports", "", -1, "set maximum number of exports for the account (-1 is unlimited)")
	cmd.Flags().Int64VarP(&params.imports.NumberValue, "imports", "", -1, "set maximum number of imports for the account (-1 is unlimited)")
	cmd.Flags().StringVarP(&params.payload.Value, "payload", "", "-1", "set maximum message payload in bytes for the account (-1 is unlimited)")
	cmd.Flags().Int64VarP(&params.subscriptions.NumberValue, "subscriptions", "", -1, "set maximum subscription for the account (-1 is unlimited)")
	cmd.Flags().BoolVarP(&params.exportsWc, "wildcard-exports", "", true, "exports can contain wildcards")

	params.AccountContextParams.BindFlags(cmd)
	params.TimeParams.BindFlags(cmd)

	return cmd
}

func init() {
	editCmd.AddCommand(createEditAccount())
}

type EditAccountParams struct {
	AccountContextParams
	SignerParams
	TimeParams
	claim         *jwt.AccountClaims
	token         string
	tags          []string
	rmTags        []string
	conns         NumberParams
	exports       NumberParams
	exportsWc     bool
	imports       NumberParams
	subscriptions NumberParams
	payload       DataParams
	data          DataParams
}

func (p *EditAccountParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.SetDefaults(ctx)
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)

	if !InteractiveFlag && ctx.NothingToDo("start", "expiry", "tag", "rm-tag", "conns", "exports", "imports", "subscriptions", "payload", "data", "wildcard-exports") {
		ctx.CurrentCmd().SilenceUsage = false
		return fmt.Errorf("specify an edit option")
	}
	return nil
}

func (p *EditAccountParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}
	return nil
}

func (p *EditAccountParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	p.claim, err = ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		return err
	}

	if !ctx.CurrentCmd().Flags().Changed("conns") {
		p.conns.NumberValue = p.claim.Limits.Conn
	}

	if !ctx.CurrentCmd().Flags().Changed("data") {
		p.data.Value = fmt.Sprintf("%d", p.claim.Limits.Data)
	}

	if !ctx.CurrentCmd().Flags().Changed("exports") {
		p.exports.NumberValue = p.claim.Limits.Exports
	}

	if !ctx.CurrentCmd().Flags().Changed("imports") {
		p.imports.NumberValue = p.claim.Limits.Imports
	}

	if !ctx.CurrentCmd().Flags().Changed("payload") {
		p.payload.Value = fmt.Sprintf("%d", p.claim.Limits.Payload)
	}

	if !ctx.CurrentCmd().Flags().Changed("subscriptions") {
		p.subscriptions.NumberValue = p.claim.Limits.Subs
	}

	return err
}

func (p *EditAccountParams) PostInteractive(ctx ActionCtx) error {
	var err error
	if err = p.conns.Edit("max connections"); err != nil {
		return err
	}

	if err = p.data.Edit("max data"); err != nil {
		return err
	}

	if err = p.exports.Edit("max exports (-1 unlimited)"); err != nil {
		return err
	}

	if err = p.imports.Edit("max imports (-1 unlimited)"); err != nil {
		return err
	}

	if err = p.payload.Edit("max payload (-1 unlimited)"); err != nil {
		return err
	}

	if err = p.subscriptions.Edit("max subscriptions (-1 unlimited)"); err != nil {
		return err
	}

	if err = p.TimeParams.Edit(); err != nil {
		return err
	}

	if err := p.SignerParams.Edit(ctx); err != nil {
		return err
	}
	return nil
}

func (p *EditAccountParams) Validate(ctx ActionCtx) error {
	var err error
	if err = p.TimeParams.Validate(); err != nil {
		return err
	}
	if err = p.SignerParams.Resolve(ctx); err != nil {
		return err
	}
	return nil
}

func (p *EditAccountParams) Run(ctx ActionCtx) error {
	var err error
	if p.TimeParams.IsStartChanged() {
		p.claim.NotBefore, _ = p.TimeParams.StartDate()
	}

	if p.TimeParams.IsExpiryChanged() {
		p.claim.Expires, _ = p.TimeParams.ExpiryDate()
	}

	p.claim.Tags.Add(p.tags...)
	p.claim.Tags.Remove(p.rmTags...)
	sort.Strings(p.claim.Tags)

	p.claim.Limits.Conn = p.conns.NumberValue
	p.claim.Limits.Data, err = p.data.NumberValue()
	if err != nil {
		return fmt.Errorf("error parsing %s: %s", "data", p.data.Value)
	}
	p.claim.Limits.Exports = p.exports.NumberValue
	p.claim.Limits.WildcardExports = p.exportsWc
	p.claim.Limits.Imports = p.imports.NumberValue
	p.claim.Limits.Payload, err = p.payload.NumberValue()
	if err != nil {
		return fmt.Errorf("error parsing %s: %s", "payload", p.data.Value)
	}
	p.claim.Limits.Subs = p.subscriptions.NumberValue

	p.token, err = p.claim.Encode(p.signerKP)
	if err != nil {
		return err
	}
	return ctx.StoreCtx().Store.StoreClaim([]byte(p.token))
}
