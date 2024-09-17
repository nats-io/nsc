/*
 * Copyright 2018-2024 The NATS Authors
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
	"strconv"
	"strings"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
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
	params := &EditAccountParams{}
	cmd := &cobra.Command{
		Use:          "account",
		Short:        "Edit an account",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, params)
		},
	}
	cmd.Flags().BoolVarP(&params.strictTags, "strict-tags", "", false, "allow tags to be case-sensitive, default false")
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
	cmd.Flags().VarP(&params.MemStorage, "mem-storage", "", "")
	cmd.Flags().VarP(&params.DiskStorage, "disk-storage", "", "")
	params.Streams = -1
	cmd.Flags().VarP(&params.Streams, "streams", "", "")
	params.Consumer = -1
	cmd.Flags().VarP(&params.Consumer, "consumer", "", "")
	cmd.Flags().MarkHidden("mem-storage")
	cmd.Flags().MarkHidden("disk-storage")
	cmd.Flags().MarkHidden("streams")
	cmd.Flags().MarkHidden("consumer")
	cmd.Flags().MarkDeprecated("mem-storage", "it got renamed to --js-mem-storage")
	cmd.Flags().MarkDeprecated("disk-storage", "it got renamed to --js-disk-storage")
	cmd.Flags().MarkDeprecated("streams", "it got renamed to --js-streams")
	cmd.Flags().MarkDeprecated("consumer", "it got renamed to --js-consumer")

	cmd.Flags().BoolVarP(&params.exportsWc, "wildcard-exports", "", true, "exports can contain wildcards")
	cmd.Flags().BoolVarP(&params.disallowBearer, "disallow-bearer", "", false, "require user jwt to not be bearer token")
	cmd.Flags().StringSliceVarP(&params.rmSigningKeys, "rm-sk", "", nil, "remove signing key - comma separated list or option can be specified multiple times")
	cmd.Flags().StringVarP(&params.description, "description", "", "", "Description for this account")
	cmd.Flags().StringVarP(&params.infoUrl, "info-url", "", "", "Link for more info on this account")
	params.PermissionsParams.bindSetFlags(cmd, "default permissions")
	params.PermissionsParams.bindRemoveFlags(cmd, "default permissions")

	// jetstream limits
	// tier applies to all assets
	params.Tier = 0
	cmd.Flags().IntVarP(&params.Tier, "js-tier", "", 0, "JetStream: replication tier (0 creates a configuration that applies to all assets) ")
	cmd.Flags().IntVarP(&params.DeleteTier, "rm-js-tier", "", -1, "JetStream: remove replication limits for the specified tier (0 is the global tier) this flag is exclusive of all other js flags")
	cmd.Flags().VarP(&params.MemStorage, "js-mem-storage", "", "JetStream: set maximum memory storage in bytes for the account (-1 is unlimited / 0 disabled) (units: k/m/g/t kib/mib/gib/tib)")
	cmd.Flags().VarP(&params.DiskStorage, "js-disk-storage", "", "JetStream: set maximum disk storage in bytes for the account (-1 is unlimited / 0 disabled) (units: k/m/g/t kib/mib/gib/tib)")
	params.Streams = -1
	cmd.Flags().VarP(&params.Streams, "js-streams", "", "JetStream: set maximum streams for the account (-1 is unlimited)")
	params.Consumer = -1
	cmd.Flags().VarP(&params.Consumer, "js-consumer", "", "JetStream: set maximum consumer for the account (-1 is unlimited)")
	params.MemMaxStreamBytes = -1
	cmd.Flags().VarP(&params.MemMaxStreamBytes, "js-max-mem-stream", "", "JetStream: set maximum size of a memory stream for the account (-1 is unlimited / 0 disabled) (units: k/m/g/t kib/mib/gib/tib)")
	params.DiskMaxStreamBytes = -1
	cmd.Flags().VarP(&params.DiskMaxStreamBytes, "js-max-disk-stream", "", "JetStream: set maximum size of a disk stream for the account (-1 is unlimited / 0 disabled) (units: k/m/g/t kib/mib/gib/tib)")
	cmd.Flags().BoolVarP(&params.MaxBytesRequired, "js-max-bytes-required", "", false, "JetStream: set whether max stream is required when creating a stream")
	params.MaxAckPending = -1
	cmd.Flags().VarP(&params.MaxAckPending, "js-max-ack-pending", "", "JetStream: set number of maximum acks that can be pending for a consumer in the account")

	cmd.Flags().StringVarP(&params.AccountContextParams.Name, "name", "n", "", "account to edit")
	cmd.Flags().BoolVarP(&params.disableJetStream, "js-disable", "", false, "disables all JetStream limits in the account by deleting any limits")
	cmd.Flags().IntVarP(&params.enableJetStream, "js-enable", "", -1, "enables JetStream for the specified tier")

	params.signingKeys.BindFlags("sk", "", nkeys.PrefixByteAccount, cmd)
	params.TimeParams.BindFlags(cmd)

	cmd.Flags().StringVarP(&params.traceContextSubject, "trace-context-subject", "", "trace.messages", "sets the subject where w3c trace context information is sent. Set to \"\" to disable")
	cmd.Flags().VarP(&params.traceContextSampling, "trace-context-sampling", "", "set the trace context sampling rate (1-100) - 0 default is 100")

	return cmd
}

func init() {
	editCmd.AddCommand(createEditAccount())
}

type JetStreamLimitParams struct {
	Tier               int
	DeleteTier         int
	MemStorage         NumberParams
	DiskStorage        NumberParams
	Streams            NumberParams
	Consumer           NumberParams
	MemMaxStreamBytes  NumberParams
	DiskMaxStreamBytes NumberParams
	MaxBytesRequired   bool
	MaxAckPending      NumberParams
	hasJSSetParams     bool
}

type EditAccountParams struct {
	AccountContextParams
	SignerParams
	GenericClaimsParams
	PermissionsParams
	JetStreamLimitParams
	claim                *jwt.AccountClaims
	token                string
	infoUrl              string
	description          string
	conns                NumberParams
	leafConns            NumberParams
	exports              NumberParams
	disallowBearer       bool
	exportsWc            bool
	imports              NumberParams
	subscriptions        NumberParams
	payload              NumberParams
	data                 NumberParams
	signingKeys          SigningKeysParams
	rmSigningKeys        []string
	disableJetStream     bool
	enableJetStream      int
	traceContextSubject  string
	traceContextSampling NumberParams
}

func (p *EditAccountParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.Name = NameFlagOrArgument(p.AccountContextParams.Name, ctx)
	if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
		return err
	}
	p.SignerParams.SetDefaults(nkeys.PrefixByteOperator, true, ctx)

	hasDeleteTier := ctx.AnySet("rm-js-tier")
	p.hasJSSetParams = ctx.AnySet("js-tier",
		"js-mem-storage",
		"js-disk-storage",
		"js-streams",
		"js-consumer",
		"js-max-mem-stream",
		"js-max-disk-stream",
		"js-max-bytes-required",
		"js-max-ack-pending",
		"js-enable",
	)

	if hasDeleteTier && p.hasJSSetParams {
		return fmt.Errorf("rm-js-tier is exclusive of all other js options")
	}

	if p.disableJetStream && (p.hasJSSetParams || hasDeleteTier) {
		return fmt.Errorf("js-disable is exclusive of all other js options")
	}

	hasEnableTier := ctx.AnySet("js-enable")
	p.hasJSSetParams = ctx.AnySet("js-tier",
		"js-mem-storage",
		"js-disk-storage",
		"js-streams",
		"js-consumer",
		"js-max-mem-stream",
		"js-max-disk-stream",
		"js-max-bytes-required",
		"js-max-ack-pending",
		"rm-js-tier",
	)

	if hasEnableTier && p.hasJSSetParams {
		return fmt.Errorf("js-enable is exclusive of all other js options")
	}

	if p.disableJetStream && (p.hasJSSetParams || hasEnableTier) {
		return fmt.Errorf("js-enable is exclusive of all other js options")
	}

	if !InteractiveFlag && ctx.NothingToDo(
		"start", "expiry", "tag", "rm-tag", "conns", "leaf-conns", "exports", "imports", "subscriptions",
		"payload", "data", "wildcard-exports", "sk", "rm-sk", "description", "info-url", "response-ttl", "allow-pub-response",
		"allow-pub-response", "allow-pub", "allow-pubsub", "allow-sub", "deny-pub", "deny-pubsub", "deny-sub",
		"rm-response-perms", "rm", "max-responses", "mem-storage", "disk-storage", "streams", "consumer", "disallow-bearer",
		"js-tier",
		"rm-js-tier",
		"js-mem-storage",
		"js-disk-storage",
		"js-streams",
		"js-consumer",
		"js-max-mem-stream",
		"js-max-disk-stream",
		"js-max-bytes-required",
		"js-max-ack-pending",
		"js-disable",
		"js-enable",
		"trace-context-subject",
		"trace-context-sampling",
	) {
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

func (p *EditAccountParams) getTierLimits(tier int) (*jwt.JetStreamLimits, error) {
	// the source of existing limits in the JWT
	var src *jwt.JetStreamLimits
	switch tier {
	case 0:
		src = &p.claim.Limits.JetStreamLimits
	default:
		if len(p.claim.Limits.JetStreamTieredLimits) == 0 {
			src = &jwt.JetStreamLimits{}
		} else {

			v, ok := p.claim.Limits.JetStreamTieredLimits[fmt.Sprintf("R%d", tier)]
			if !ok {
				v = jwt.JetStreamLimits{}
			}
			src = &v
		}
	}
	return src, nil
}

func (p *EditAccountParams) doDisableJetStream(r *store.Report) error {
	if !p.disableJetStream {
		return nil
	}
	p.claim.Limits.JetStreamLimits = jwt.JetStreamLimits{}
	r.AddOK("deleted global limit")
	for k := range p.claim.Limits.JetStreamTieredLimits {
		r.AddOK("deleted tier limit %s", k)
	}
	p.claim.Limits.JetStreamTieredLimits = nil
	return nil
}

func (p *EditAccountParams) loadLimits(ctx ActionCtx, tier int) error {
	src, err := p.getTierLimits(tier)
	if err != nil {
		return err
	}
	if !jsLimitsSet(src) || p.JetStreamLimitParams.DeleteTier != -1 {
		// we don't have pre-existing limits, so we can skip this
		return nil
	}
	if !(ctx.CurrentCmd().Flags().Changed("js-mem-storage") || ctx.CurrentCmd().Flags().Changed("mem-storage")) {
		p.JetStreamLimitParams.MemStorage = NumberParams(src.MemoryStorage)
	}
	if !(ctx.CurrentCmd().Flags().Changed("js-disk-storage") || ctx.CurrentCmd().Flags().Changed("disk-storage")) {
		p.JetStreamLimitParams.DiskStorage = NumberParams(src.DiskStorage)
	}
	if !(ctx.CurrentCmd().Flags().Changed("js-streams") || ctx.CurrentCmd().Flags().Changed("streams")) {
		p.JetStreamLimitParams.Streams = NumberParams(src.Streams)
	}
	if !(ctx.CurrentCmd().Flags().Changed("js-consumer") || ctx.CurrentCmd().Flags().Changed("consumer")) {
		p.JetStreamLimitParams.Consumer = NumberParams(src.Consumer)
	}
	if !ctx.CurrentCmd().Flags().Changed("js-max-mem-stream") {
		p.JetStreamLimitParams.MemMaxStreamBytes = NumberParams(src.MemoryMaxStreamBytes)
	}
	if !ctx.CurrentCmd().Flags().Changed("js-max-disk-stream") {
		p.JetStreamLimitParams.DiskMaxStreamBytes = NumberParams(src.DiskMaxStreamBytes)
	}
	if !ctx.CurrentCmd().Flags().Changed("js-max-ack-pending") {
		p.JetStreamLimitParams.MaxAckPending = NumberParams(src.MaxAckPending)
	}
	if !ctx.CurrentCmd().Flags().Changed("js-max-ack-required") {
		p.JetStreamLimitParams.MaxBytesRequired = src.MaxBytesRequired
	}
	return nil
}

func jsLimitsSet(l *jwt.JetStreamLimits) bool {
	return l.MemoryStorage != 0 || l.DiskStorage != 0 || l.Streams != 0 ||
		l.Consumer != 0 || l.MaxAckPending != 0 || l.MemoryMaxStreamBytes != 0 ||
		l.DiskMaxStreamBytes != 0 || l.MaxBytesRequired
}

func (p *EditAccountParams) validJsLimitConfig() error {
	// do some early sanity on tiered / global limits
	// if we have tier limits, global limits must not be set
	tiered := len(p.claim.Limits.JetStreamTieredLimits)
	keys := make([]string, tiered)
	i := 0
	for k := range p.claim.Limits.JetStreamTieredLimits {
		keys[i] = k
		i++
	}
	global, err := p.getTierLimits(0)
	if err != nil {
		return err
	}
	globalIsSet := jsLimitsSet(global)

	// don't validate if removing as this will possibly fix the config or running interactive
	if p.DeleteTier > -1 || InteractiveFlag {
		return nil
	}

	// we have a bad configuration - this actually shouldn't trigger because
	// the JWT library will discard the global value if tiered limits
	// are present - however we keep this here just in case
	// https://github.com/nats-io/jwt/blob/main/v2/decoder_account.go#L48
	if tiered > 0 && globalIsSet {
		return fmt.Errorf("configuration cannot contain both global and tiered limits '%s' - please use the --rm-js-tier to remove undesired tier(s)", strings.Join(keys, ","))
	}
	// trying to add global to tiered (only if js set params have been passed)
	if tiered > 0 && p.Tier == 0 && p.hasJSSetParams {
		return fmt.Errorf("cannot set a jetstream global limit when a configuration has tiered limits '%s'", strings.Join(keys, ","))
	}
	// trying to add tiered to global
	if globalIsSet && p.Tier > 0 && p.hasJSSetParams {
		return errors.New("cannot set a jetstream tier limit when a configuration has a global limit")
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

	if err = p.validJsLimitConfig(); err != nil {
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

	if !ctx.CurrentCmd().Flags().Changed("description") {
		p.description = p.claim.Description
	}

	if !ctx.CurrentCmd().Flags().Changed("info-url") {
		p.infoUrl = p.claim.InfoURL
	}

	if err := p.loadLimits(ctx, p.Tier); err != nil {
		return err
	}

	return err
}

func (p *EditAccountParams) tierLabel() string {
	if p.Tier > 0 {
		return fmt.Sprintf("R%d", p.Tier)
	}
	return "global"
}

func (p *EditAccountParams) PostInteractiveTier(_ctx ActionCtx) error {
	target := &p.JetStreamLimitParams

	ok, err := cli.Confirm("set JetStream limits", false)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}

	replication, err := cli.Prompt("edit tier (0 matches all tiers)", "0", cli.Val(func(s string) error {
		v, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		if v < 0 {
			return errors.New("replication must be 0 or greater")
		}
		// make sure we don't have tiered
		if v == 0 && len(p.claim.Limits.JetStreamTieredLimits) > 0 {
			return errors.New("configuration has tier limits - global limits are not allowed")
		}
		// make sure we don't have global
		if v > 0 && jsLimitsSet(&p.claim.Limits.JetStreamLimits) {
			return errors.New("configuration has global limits - tiered limits are not allowed")
		}
		return nil
	}))
	if err != nil {
		return err
	}
	p.Tier, err = strconv.Atoi(replication)
	if err != nil {
		return err
	}

	if err = target.MemStorage.Edit("max mem storage (-1 unlimited / 0 disabled)"); err != nil {
		return err
	}

	if err = target.DiskStorage.Edit("max disk storage (-1 unlimited / 0 disabled)"); err != nil {
		return err
	}

	if target.MemStorage != 0 || target.DiskStorage != 0 {
		if err = target.Streams.Edit("max streams (-1 unlimited)"); err != nil {
			return err
		}
		if err = target.Consumer.Edit("max consumer (-1 unlimited)"); err != nil {
			return err
		}
		if err = target.MemMaxStreamBytes.Edit("max size for a memory stream (-1 unlimited)"); err != nil {
			return err
		}
		if err = target.DiskMaxStreamBytes.Edit("max size for a disk stream (-1 unlimited)"); err != nil {
			return err
		}
		if err = target.MaxAckPending.Edit("max number of pending acks for a consumer"); err != nil {
			return err
		}

		target.MaxBytesRequired, err = cli.Confirm("require max bytes when creating a stream", false)
		if err != nil {
			return err
		}
	}

	return nil
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

	if err = p.PostInteractiveTier(ctx); err != nil {
		return err
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

	ok, err := cli.Confirm("Enable context tracing?", false)
	if err != nil {
		return err
	}
	if ok {
		p.traceContextSubject, err = cli.Prompt("Trace context subject?", p.traceContextSubject)
		if err != nil {
			return err
		}
		if err = p.traceContextSampling.Edit("Trace context sampling rate [1-100]"); err != nil {
			return err
		}
		if p.traceContextSampling.Int64() < 0 {
			_ = p.traceContextSampling.Set("0")
		} else if p.traceContextSampling.Int64() > 100 {
			_ = p.traceContextSampling.Set("100")
		}
	}

	return nil
}

func (p *EditAccountParams) checkSystemAccount(ctx ActionCtx) error {
	// if we are not editing system account ignore
	if op, _ := ctx.StoreCtx().Store.ReadOperatorClaim(); op.SystemAccount != p.claim.Subject {
		return nil
	}

	if p.claim.Limits.JetStreamTieredLimits != nil {
		return errors.New("system account cannot have JetStream limits - please rerun with --js-disable")
	}

	var mustUnset []string

	if p.Tier != 0 {
		mustUnset = append(mustUnset, "--js-tier")
	}
	if p.MemStorage > 0 {
		mustUnset = append(mustUnset, "--js-mem-storage")
	}
	if p.DiskStorage > 0 {
		mustUnset = append(mustUnset, "--js-disk-storage")
	}
	if p.Streams > 0 {
		mustUnset = append(mustUnset, "--js-streams")
	}
	if p.Consumer > 0 {
		mustUnset = append(mustUnset, "--js-consumer")
	}
	if p.MemMaxStreamBytes > 0 {
		mustUnset = append(mustUnset, "--js-max-mem-stream")
	}
	if p.DiskMaxStreamBytes > 0 {
		mustUnset = append(mustUnset, "--js-max-disk-stream")
	}
	if p.MaxBytesRequired {
		mustUnset = append(mustUnset, "--js-max-bytes-required")
	}
	if p.MaxAckPending > 0 {
		mustUnset = append(mustUnset, "--js-max-ack-pending")
	}

	if len(mustUnset) == 0 {
		// no user specified values set - so set to zero/false
		// reset all the flags to zero
		p.Tier = 0
		p.Consumer = 0
		p.Streams = 0
		p.DiskStorage = 0
		p.MemStorage = 0
		p.MemMaxStreamBytes = 0
		p.DiskMaxStreamBytes = 0
		p.MaxBytesRequired = false
		p.MaxAckPending = 0
	} else {
		return fmt.Errorf("system account cannot have jetstream related settings - please rerun without: %s", strings.Join(mustUnset, " "))
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
	if err = p.checkSystemAccount(ctx); err != nil {
		return err
	}
	if err := p.PermissionsParams.Validate(); err != nil {
		return err
	}
	if p.disallowBearer {
		usrs, _ := ctx.StoreCtx().Store.ListEntries(store.Accounts, p.AccountContextParams.Name, store.Users)
		for _, usrName := range usrs {
			uc, err := ctx.StoreCtx().Store.ReadUserClaim(p.AccountContextParams.Name, usrName)
			if err != nil {
				return err
			}
			if uc.BearerToken {
				return fmt.Errorf("user %q in account %q uses bearer token (needs to be deleted/changed first)",
					usrName, p.AccountContextParams.Name)
			}
		}
	}

	if p.traceContextSubject != "" {
		subj := jwt.Subject(p.traceContextSubject)
		var v jwt.ValidationResults
		subj.Validate(&v)
		if !v.IsEmpty() {
			errs := v.Errors()
			return errs[0]
		}
		if subj.HasWildCards() {
			return fmt.Errorf("tracing subjects cannot contain wildcards: %q", subj)
		}
	}
	flags := ctx.CurrentCmd().Flags()
	if flags.Changed("trace-context-sampling") {
		if p.claim.Trace == nil {
			p.claim.Trace = &jwt.MsgTrace{}
		}
		// we are changing the sampling do we have a subject
		if p.claim.Trace.Destination == "" {
			if p.traceContextSubject == "" || !flags.Changed("trace-context-subject") {
				return errors.New("trace-context-sampling requires a subject")
			}
		}

		if p.traceContextSampling.Int64() < 0 || p.traceContextSampling.Int64() > 100 {
			return errors.New("tracing sampling rate must be between 1-100")
		}
	}

	if p.enableJetStream > -1 {
		tier, err := p.getTierLimits(p.enableJetStream)
		if err != nil {
			return err
		}
		if jsLimitsSet(tier) {
			label := "global"
			if p.enableJetStream > 0 {
				label = fmt.Sprintf("R%d", p.enableJetStream)
			}
			return fmt.Errorf("jetstream tier %s is already enabled", label)
		}
	}

	return nil
}

func (p *EditAccountParams) applyLimits(ctx ActionCtx, r *store.Report) error {
	flags := ctx.CurrentCmd().Flags()

	limits, err := p.getTierLimits(p.Tier)
	if err != nil {
		return err
	}
	params := &p.JetStreamLimitParams

	// on delete or enable we don't honor any of the JS options
	if p.DeleteTier != -1 || p.enableJetStream != -1 {
		params.MemMaxStreamBytes = 0
		params.DiskMaxStreamBytes = 0
		params.MaxAckPending = 0
		params.Streams = 0
		params.Consumer = 0
		params.DiskStorage = 0
		params.MemStorage = 0
		params.MaxBytesRequired = false
	}

	if p.DeleteTier != -1 {
		switch p.DeleteTier {
		case -1:
			break
		case 0:
			// values are zeroed by the params which are zeroed above
			p.claim.Limits.JetStreamLimits = jwt.JetStreamLimits{}
			r.AddOK("deleted global limit")
		default:
			if p.claim.Limits.JetStreamTieredLimits != nil {
				label := fmt.Sprintf("R%d", p.DeleteTier)
				_, ok := p.claim.Limits.JetStreamTieredLimits[label]
				if ok {
					delete(p.claim.Limits.JetStreamTieredLimits, label)
					r.AddOK("deleted tier limit %s", label)
				} else {
					return fmt.Errorf("account doesn't have tier %s limit", label)
				}
			} else {
				return errors.New("account doesn't have tier limits")
			}
		}
	}

	if p.DeleteTier != -1 {
		return nil
	}

	if p.disableJetStream {
		return p.doDisableJetStream(r)
	}

	if p.enableJetStream != -1 {
		switch p.enableJetStream {
		case -1:
			break
		case 0:
			// values are zeroed by the params which are zeroed above
			p.claim.Limits.JetStreamLimits = jwt.JetStreamLimits{
				DiskStorage:   -1,
				MemoryStorage: -1,
			}
			r.AddOK("enabled global limit")
		default:
			label := fmt.Sprintf("R%d", p.enableJetStream)
			_, ok := p.claim.Limits.JetStreamTieredLimits[label]
			if ok {
				return fmt.Errorf("tier limit %s is already enabled", label)
			} else {
				if p.claim.Limits.JetStreamTieredLimits == nil {
					p.claim.Limits.JetStreamTieredLimits = make(map[string]jwt.JetStreamLimits)
				}
				p.claim.Limits.JetStreamTieredLimits[label] = jwt.JetStreamLimits{
					DiskStorage:   -1,
					MemoryStorage: -1,
				}
				r.AddOK("enabled tier limit %s", label)
			}
		}
	}

	if p.enableJetStream != -1 {
		return nil
	}

	label := p.tierLabel()

	limits.Streams = params.Streams.Int64()
	if flags.Changed("js-streams") {
		r.AddOK("changed %s max streams to %d", label, limits.Streams)
	}

	limits.Consumer = params.Consumer.Int64()
	if flags.Changed("js-consumer") {
		r.AddOK("changed %s max consumer to %d", label, limits.Consumer)
	}

	limits.MemoryStorage = params.MemStorage.Int64()
	if flags.Changed("js-mem-storage") {
		r.AddOK("changed %s max mem storage to %d", label, limits.MemoryStorage)
	}

	limits.MemoryMaxStreamBytes = params.MemMaxStreamBytes.Int64()
	if flags.Changed("js-max-mem-stream") {
		r.AddOK("changed %s max memory stream to %d", label, limits.MemoryMaxStreamBytes)
	}

	limits.DiskStorage = params.DiskStorage.Int64()
	if flags.Changed("js-disk-storage") {
		r.AddOK("changed %s max disk storage to %d", label, limits.DiskStorage)
	}

	limits.DiskMaxStreamBytes = params.DiskMaxStreamBytes.Int64()
	if flags.Changed("js-max-disk-stream") {
		r.AddOK("changed %s max disk stream to %d", label, limits.DiskMaxStreamBytes)
	}
	limits.MaxAckPending = params.MaxAckPending.Int64()
	if flags.Changed("js-max-ack-pending") {
		r.AddOK("changed %s max ack pending to %d", label, limits.MaxAckPending)
	}
	limits.MaxBytesRequired = params.MaxBytesRequired
	if flags.Changed("js-max-ack-required") {
		r.AddOK("changed %s max bytes required to %t", label, limits.MaxBytesRequired)
	}

	if p.Tier == 0 {
		p.claim.Limits.JetStreamLimits = *limits
	} else {
		if p.claim.Limits.JetStreamTieredLimits == nil {
			p.claim.Limits.JetStreamTieredLimits = make(map[string]jwt.JetStreamLimits)
		}
		p.claim.Limits.JetStreamTieredLimits[p.tierLabel()] = *limits
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

	p.claim.Limits.DisallowBearer = p.disallowBearer
	if flags.Changed("disallow-bearer") {
		r.AddOK("changed disallow bearer to %t", p.claim.Limits.DisallowBearer)
	}

	p.claim.Limits.Imports = p.imports.Int64()
	if flags.Changed("imports") {
		r.AddOK("changed max imports to %d", p.claim.Limits.Imports)
	}

	p.claim.Limits.Payload = p.payload.Int64()
	if flags.Changed("payload") {
		r.AddOK("changed max payload size to %d", p.claim.Limits.Payload)
	}

	p.claim.Limits.Subs = p.subscriptions.Int64()
	if flags.Changed("subscriptions") {
		r.AddOK("changed max subscriptions to %d", p.claim.Limits.Subs)
	}

	if err := p.applyLimits(ctx, r); err != nil {
		return r, err
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

	// if they provided the flag we change it
	if flags.Changed("trace-context-subject") {
		// if they set us to "", we disable it
		if p.traceContextSubject == "" {
			p.claim.Trace = nil
			r.AddOK("disabled trace context")
		} else {
			p.claim.Trace = &jwt.MsgTrace{}
			p.claim.Trace.Destination = jwt.Subject(p.traceContextSubject)
			r.AddOK("changed trace context subject to %q", p.claim.Trace.Destination)
		}
	}

	if flags.Changed("trace-context-sampling") {
		if p.claim.Trace == nil {
			return r, errors.New("cannot set context sampling rate when disabling the trace context")
		}
		// we already validated that the subject is there either existing or new
		p.claim.Trace.Sampling = int(p.traceContextSampling.Int64())
		r.AddOK("changed trace context sampling to %d%%", p.claim.Trace.Sampling)
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
