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

	"github.com/nats-io/nsc/cmd/store"

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
				d, err := jwt.DecorateJWT(string(params.token))
				if err != nil {
					return err
				}
				_ = Write("--", d)

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
	cmd.Flags().Int64VarP(&params.leafConns.NumberValue, "leaf-conns", "", 0, "set maximum active leaf node connections for the account (-1 is unlimited)")
	cmd.Flags().StringVarP(&params.data.Value, "data", "", "-1", "set maximum data in bytes for the account (-1 is unlimited)")
	cmd.Flags().Int64VarP(&params.exports.NumberValue, "exports", "", -1, "set maximum number of exports for the account (-1 is unlimited)")
	cmd.Flags().Int64VarP(&params.imports.NumberValue, "imports", "", -1, "set maximum number of imports for the account (-1 is unlimited)")
	cmd.Flags().StringVarP(&params.payload.Value, "payload", "", "-1", "set maximum message payload in bytes for the account (-1 is unlimited)")
	cmd.Flags().Int64VarP(&params.subscriptions.NumberValue, "subscriptions", "", -1, "set maximum subscription for the account (-1 is unlimited)")
	cmd.Flags().BoolVarP(&params.exportsWc, "wildcard-exports", "", true, "exports can contain wildcards")
	cmd.Flags().StringSliceVarP(&params.rmSigningKeys, "rm-sk", "", nil, "remove signing key - comma separated list or option can be specified multiple times")

	params.AccountContextParams.BindFlags(cmd)
	params.signingKeys.BindFlags("sk", "", nkeys.PrefixByteAccount, cmd)
	params.TimeParams.BindFlags(cmd)

	return cmd
}

func init() {
	editCmd.AddCommand(createEditAccount())
}

type EditAccountParams struct {
	AccountContextParams
	SignerParams
	GenericClaimsParams
	claim         *jwt.AccountClaims
	token         string
	conns         NumberParams
	leafConns     NumberParams
	exports       NumberParams
	exportsWc     bool
	imports       NumberParams
	subscriptions NumberParams
	payload       DataParams
	data          DataParams
	signingKeys   SigningKeysParams
	rmSigningKeys []string
}

func (p *EditAccountParams) SetDefaults(ctx ActionCtx) error {
	if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
		return err
	}
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)

	if !InteractiveFlag && ctx.NothingToDo("start", "expiry", "tag", "rm-tag", "conns", "leaf-conns", "exports", "imports", "subscriptions", "payload", "data", "wildcard-exports", "sk", "rm-sk") {
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

	if !ctx.CurrentCmd().Flags().Changed("leaf-conns") {
		p.leafConns.NumberValue = p.claim.Limits.LeafNodeConn
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
	if err = p.signingKeys.Edit(); err != nil {
		return err
	}

	if err = p.conns.Edit("max connections (-1 unlimited)"); err != nil {
		return err
	}

	if err = p.leafConns.Edit("max leaf node connections (-1 unlimited)"); err != nil {
		return err
	}

	if err = p.data.Edit("max data (-1 unlimited)"); err != nil {
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

	if p.claim.NotBefore > 0 {
		p.GenericClaimsParams.Start = UnixToDate(p.claim.NotBefore)
	}
	if p.claim.Expires > 0 {
		p.GenericClaimsParams.Expiry = UnixToDate(p.claim.Expires)
	}
	if err = p.GenericClaimsParams.Edit(); err != nil {
		return err
	}

	if err := p.SignerParams.Edit(ctx); err != nil {
		return err
	}
	return nil
}

func (p *EditAccountParams) Validate(ctx ActionCtx) error {
	var err error
	if err = p.signingKeys.Valid(); err != nil {
		return err
	}
	if err = p.GenericClaimsParams.Valid(); err != nil {
		return err
	}
	if err = p.SignerParams.Resolve(ctx); err != nil {
		return err
	}
	return nil
}

func (p *EditAccountParams) Run(ctx ActionCtx) (store.Status, error) {
	var err error
	keys, _ := p.signingKeys.PublicKeys()
	if len(keys) > 0 {
		p.claim.SigningKeys.Add(keys...)
	}
	p.claim.SigningKeys.Remove(p.rmSigningKeys...)

	if err := p.GenericClaimsParams.Run(ctx, p.claim); err != nil {
		return nil, err
	}

	p.claim.Limits.Conn = p.conns.NumberValue
	p.claim.Limits.LeafNodeConn = p.leafConns.NumberValue
	p.claim.Limits.Data, err = p.data.NumberValue()
	if err != nil {
		return nil, fmt.Errorf("error parsing %s: %s", "data", p.data.Value)
	}
	p.claim.Limits.Exports = p.exports.NumberValue
	p.claim.Limits.WildcardExports = p.exportsWc
	p.claim.Limits.Imports = p.imports.NumberValue
	p.claim.Limits.Payload, err = p.payload.NumberValue()
	if err != nil {
		return nil, fmt.Errorf("error parsing %s: %s", "payload", p.data.Value)
	}
	p.claim.Limits.Subs = p.subscriptions.NumberValue
	p.token, err = p.claim.Encode(p.signerKP)
	if err != nil {
		return nil, err
	}
	return ctx.StoreCtx().Store.StoreClaim([]byte(p.token))
}
