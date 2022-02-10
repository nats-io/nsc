/*
 * Copyright 2018-2021 The NATS Authors
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

	"github.com/nats-io/nsc/cmd/store"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/spf13/cobra"
)

func validatorUrlOrEmpty() cli.Opt {
	return cli.Val(func(v string) error {
		if v == "" {
			return nil
		}
		return cli.URLValidator("http", "https")(v)
	})
}

func validatorMaxLen(max int) cli.Opt {
	return cli.Val(func(v string) error {
		if len(v) > max {
			return fmt.Errorf("value exceeds %d character", max)
		}
		return nil
	})
}

func createEditAccount() *cobra.Command {
	var params EditAccountParams
	cmd := &cobra.Command{
		Use:          "account",
		Short:        "Edit an account",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().StringSliceVarP(&params.tags, "tag", "", nil, "add tags for user - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.rmTags, "rm-tag", "", nil, "remove tag - comma separated list or option can be specified multiple times")
	params.conns = -1
	cmd.Flags().VarP(&params.conns, "conns", "", "set maximum active connections for the account (-1 is unlimited)")
	cmd.Flags().VarP(&params.leafConns, "leaf-conns", "", "set maximum active leaf node connections for the account (-1 is unlimited)")
	params.data = -1
	cmd.Flags().VarP(&params.data, "data", "", "set maximum data in bytes for the account (-1 is unlimited)")
	params.exports = -1
	cmd.Flags().VarP(&params.exports, "exports", "", "set maximum number of exports for the account (-1 is unlimited)")
	params.imports = -1
	cmd.Flags().VarP(&params.imports, "imports", "", "set maximum number of imports for the account (-1 is unlimited)")
	params.payload = -1
	cmd.Flags().VarP(&params.payload, "payload", "", "set maximum message payload in bytes for the account (-1 is unlimited)")
	params.subscriptions = -1
	cmd.Flags().VarP(&params.subscriptions, "subscriptions", "", "set maximum subscription for the account (-1 is unlimited)")
	// changed flag names by prefixing them with js-
	// to replace them mark the old names as hidden (so using them does not break) and add new flags with correct name
	cmd.Flags().VarP(&params.memStorage, "mem-storage", "", "")
	cmd.Flags().VarP(&params.diskStorage, "disk-storage", "", "")
	params.streams = -1
	cmd.Flags().VarP(&params.streams, "streams", "", "")
	params.consumer = -1
	cmd.Flags().VarP(&params.consumer, "consumer", "", "")
	cmd.Flags().MarkHidden("mem-storage")
	cmd.Flags().MarkHidden("disk-storage")
	cmd.Flags().MarkHidden("streams")
	cmd.Flags().MarkHidden("consumer")
	cmd.Flags().MarkDeprecated("mem-storage", "it got renamed to --js-mem-storage")
	cmd.Flags().MarkDeprecated("disk-storage", "it got renamed to --js-disk-storage")
	cmd.Flags().MarkDeprecated("streams", "it got renamed to --js-streams")
	cmd.Flags().MarkDeprecated("consumer", "it got renamed to --js-consumer")
	cmd.Flags().VarP(&params.memStorage, "js-mem-storage", "", "Jetstream: set maximum memory storage in bytes for the account (-1 is unlimited / 0 disabled) (units: k/m/g/t kib/mib/gib/tib)")
	cmd.Flags().VarP(&params.diskStorage, "js-disk-storage", "", "Jetstream: set maximum disk storage in bytes for the account (-1 is unlimited / 0 disabled) (units: k/m/g/t kib/mib/gib/tib)")
	params.streams = -1
	cmd.Flags().VarP(&params.streams, "js-streams", "", "Jetstream: set maximum streams for the account (-1 is unlimited)")
	params.consumer = -1
	cmd.Flags().VarP(&params.consumer, "js-consumer", "", "Jetstream: set maximum consumer for the account (-1 is unlimited)")
	cmd.Flags().VarP(&params.haResources, "js-ha-resources", "", "Jetstream: set maximum high availability resources, such as replicated streams and durable consumer, for the account (-1 unlimited / 0 ha resources disabled)")
	cmd.Flags().BoolVarP(&params.exportsWc, "wildcard-exports", "", true, "exports can contain wildcards")
	cmd.Flags().StringSliceVarP(&params.rmSigningKeys, "rm-sk", "", nil, "remove signing key - comma separated list or option can be specified multiple times")
	cmd.Flags().StringVarP(&params.description, "description", "", "", "Description for this account")
	cmd.Flags().StringVarP(&params.infoUrl, "info-url", "", "", "Link for more info on this account")
	params.PermissionsParams.bindSetFlags(cmd, "default permissions")
	params.PermissionsParams.bindRemoveFlags(cmd, "default permissions")

	cmd.Flags().StringVarP(&params.AccountContextParams.Name, "name", "n", "", "account to edit")
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
	PermissionsParams
	claim         *jwt.AccountClaims
	token         string
	infoUrl       string
	description   string
	conns         NumberParams
	leafConns     NumberParams
	exports       NumberParams
	memStorage    NumberParams
	diskStorage   NumberParams
	streams       NumberParams
	consumer      NumberParams
	haResources   NumberParams
	exportsWc     bool
	imports       NumberParams
	subscriptions NumberParams
	payload       NumberParams
	data          NumberParams
	signingKeys   SigningKeysParams
	rmSigningKeys []string
}

func (p *EditAccountParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.Name = NameFlagOrArgument(p.AccountContextParams.Name, ctx)
	if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
		return err
	}
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)

	if !InteractiveFlag && ctx.NothingToDo(
		"start", "expiry", "tag", "rm-tag", "conns", "leaf-conns", "exports", "imports", "subscriptions",
		"payload", "data", "wildcard-exports", "sk", "rm-sk", "description", "info-url", "response-ttl", "allow-pub-response",
		"allow-pub-response", "allow-pub", "allow-pubsub", "allow-sub", "deny-pub", "deny-pubsub", "deny-sub",
		"rm-response-perms", "rm", "max-responses", "mem-storage", "disk-storage", "streams", "consumer",
		"js-mem-storage", "js-disk-storage", "js-streams", "js-consumer") {
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
		p.conns = NumberParams(p.claim.Limits.Conn)
	}

	if !ctx.CurrentCmd().Flags().Changed("leaf-conns") {
		p.leafConns = NumberParams(p.claim.Limits.LeafNodeConn)
	}

	if !ctx.CurrentCmd().Flags().Changed("data") {
		p.data = NumberParams(p.claim.Limits.Data)
	}

	if !ctx.CurrentCmd().Flags().Changed("exports") {
		p.exports = NumberParams(p.claim.Limits.Exports)
	}

	if !ctx.CurrentCmd().Flags().Changed("imports") {
		p.imports = NumberParams(p.claim.Limits.Imports)
	}

	if !ctx.CurrentCmd().Flags().Changed("payload") {
		p.payload = NumberParams(p.claim.Limits.Payload)
	}

	if !ctx.CurrentCmd().Flags().Changed("subscriptions") {
		p.subscriptions = NumberParams(p.claim.Limits.Subs)
	}

	if !(ctx.CurrentCmd().Flags().Changed("js-mem-storage") || ctx.CurrentCmd().Flags().Changed("mem-storage")) {
		p.memStorage = NumberParams(p.claim.Limits.MemoryStorage)
	}

	if !(ctx.CurrentCmd().Flags().Changed("js-disk-storage") || ctx.CurrentCmd().Flags().Changed("disk-storage")) {
		p.diskStorage = NumberParams(p.claim.Limits.DiskStorage)
	}

	if !(ctx.CurrentCmd().Flags().Changed("js-streams") || ctx.CurrentCmd().Flags().Changed("streams")) {
		p.streams = NumberParams(p.claim.Limits.Streams)
	}

	if !(ctx.CurrentCmd().Flags().Changed("js-consumer") || ctx.CurrentCmd().Flags().Changed("consumer")) {
		p.consumer = NumberParams(p.claim.Limits.Consumer)
	}

	if !ctx.CurrentCmd().Flags().Changed("js-ha-resources") {
		p.haResources = NumberParams(p.claim.Limits.HaResources)
	}

	if !ctx.CurrentCmd().Flags().Changed("description") {
		p.description = p.claim.Description
	}

	if !ctx.CurrentCmd().Flags().Changed("info-url") {
		p.infoUrl = p.claim.InfoURL
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

	if err = p.memStorage.Edit("max mem storage (-1 unlimited / 0 disabled)"); err != nil {
		return err
	}

	if err = p.diskStorage.Edit("max disk storage (-1 unlimited / 0 disabled)"); err != nil {
		return err
	}

	if p.memStorage != 0 || p.diskStorage != 0 {
		if err = p.streams.Edit("max streams (-1 unlimited)"); err != nil {
			return err
		}

		if err = p.consumer.Edit("max consumer (-1 unlimited)"); err != nil {
			return err
		}

		if err = p.haResources.Edit("max high availability resources (replicated streams/durable consumer) (-1 unlimited / 0 ha resources disabled)"); err != nil {
			return err
		}
	}

	if p.claim.NotBefore > 0 {
		p.GenericClaimsParams.Start = UnixToDate(p.claim.NotBefore)
	}
	if p.claim.Expires > 0 {
		p.GenericClaimsParams.Expiry = UnixToDate(p.claim.Expires)
	}
	if err = p.GenericClaimsParams.Edit(p.claim.Tags); err != nil {
		return err
	}

	if err := p.SignerParams.Edit(ctx); err != nil {
		return err
	}

	if p.description, err = cli.Prompt("Account Description", p.description, validatorMaxLen(jwt.MaxInfoLength)); err != nil {
		return err
	}

	if p.infoUrl, err = cli.Prompt("Info url", p.infoUrl, validatorUrlOrEmpty()); err != nil {
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
	if err = p.SignerParams.ResolveWithPriority(ctx, p.claim.Issuer); err != nil {
		return err
	}
	if op, _ := ctx.StoreCtx().Store.ReadOperatorClaim(); op.SystemAccount == p.claim.Subject {
		if p.memStorage != 0 || p.diskStorage != 0 || p.consumer != 0 || p.streams != 0 {
			return fmt.Errorf("jetstream not available for system account")
		}
	}
	if err := p.PermissionsParams.Validate(); err != nil {
		return err
	}
	return nil
}

func (p *EditAccountParams) Run(ctx ActionCtx) (store.Status, error) {
	r := store.NewDetailedReport(true)
	r.ReportSum = false

	var err error
	keys, _ := p.signingKeys.PublicKeys()
	if len(keys) > 0 {
		p.claim.SigningKeys.Add(keys...)
		for _, k := range keys {
			r.AddOK("added signing key %q", k)
		}
	}
	p.claim.SigningKeys.Remove(p.rmSigningKeys...)
	for _, k := range p.rmSigningKeys {
		r.AddOK("removed signing key %q", k)
	}

	if err := p.GenericClaimsParams.Run(ctx, p.claim, r); err != nil {
		return nil, err
	}

	flags := ctx.CurrentCmd().Flags()
	p.claim.Limits.Conn = p.conns.Int64()
	if flags.Changed("conns") {
		r.AddOK("changed max connections to %d", p.claim.Limits.Conn)
	}

	p.claim.Limits.LeafNodeConn = p.leafConns.Int64()
	if flags.Changed("leaf-conns") {
		r.AddOK("changed leaf node connections to %d", p.claim.Limits.LeafNodeConn)
	}

	p.claim.Limits.Data = p.data.Int64()
	if flags.Changed("data") {
		r.AddOK("changed max data to %d bytes", p.claim.Limits.Data)
	}

	p.claim.Limits.Exports = p.exports.Int64()
	if flags.Changed("exports") {
		r.AddOK("changed max exports to %d", p.claim.Limits.Exports)
	}

	p.claim.Limits.WildcardExports = p.exportsWc
	if flags.Changed("wildcard-exports") {
		r.AddOK("changed wild card exports to %t", p.claim.Limits.WildcardExports)
	}

	p.claim.Limits.Imports = p.imports.Int64()
	if flags.Changed("imports") {
		r.AddOK("changed max imports to %d", p.claim.Limits.Imports)
	}

	p.claim.Limits.Payload = p.payload.Int64()
	if flags.Changed("payload") {
		r.AddOK("changed max imports to %d", p.claim.Limits.Payload)
	}

	p.claim.Limits.Subs = p.subscriptions.Int64()
	if flags.Changed("subscriptions") {
		r.AddOK("changed max subscriptions to %d", p.claim.Limits.Subs)
	}

	p.claim.Limits.MemoryStorage = p.memStorage.Int64()
	if flags.Changed("mem-storage") || flags.Changed("js-mem-storage") {
		r.AddOK("changed max mem storage to %d", p.claim.Limits.MemoryStorage)
	}

	p.claim.Limits.DiskStorage = p.diskStorage.Int64()
	if flags.Changed("disk-storage") || flags.Changed("js-disk-storage") {
		r.AddOK("changed max disk storage to %d", p.claim.Limits.DiskStorage)
	}

	p.claim.Limits.Streams = p.streams.Int64()
	if flags.Changed("streams") || flags.Changed("js-streams") {
		r.AddOK("changed max streams to %d", p.claim.Limits.Streams)
	}

	p.claim.Limits.Consumer = p.consumer.Int64()
	if flags.Changed("consumer") || flags.Changed("js-consumer") {
		r.AddOK("changed max consumer to %d", p.claim.Limits.Consumer)
	}

	p.claim.Limits.HaResources = p.haResources.Int64()
	if flags.Changed("js-ha-resources") {
		r.AddOK("changed high availability resources to %d", p.claim.Limits.HaResources)
	}

	p.claim.Description = p.description
	if flags.Changed("description") {
		r.AddOK(`changed description to %q`, p.claim.Description)
	}

	p.claim.InfoURL = p.infoUrl
	if flags.Changed("info-url") {
		r.AddOK(`changed info url to %q`, p.claim.InfoURL)
	}

	s, err := p.PermissionsParams.Run(&p.claim.DefaultPermissions, ctx)
	if err != nil {
		return nil, err
	}
	if s != nil {
		r.Add(s.Details...)
	}

	p.token, err = p.claim.Encode(p.signerKP)
	if err != nil {
		return nil, err
	}
	StoreAccountAndUpdateStatus(ctx, p.token, r)
	if ctx.StoreCtx().Store.IsManaged() {
		bc, err := ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
		if err != nil {
			r.AddWarning("unable to read account %q: %v", p.AccountContextParams.Name, err)
		} else {
			r.Add(DiffAccountLimits(p.claim, bc))
		}
	}
	r.AddOK("edited account %q", p.AccountContextParams.Name)

	return r, err
}
