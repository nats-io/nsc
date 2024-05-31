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
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
)

func createEditUserCmd() *cobra.Command {
	var params EditUserParams
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Edit an user",
		Long: `# Edit permissions so that the user can publish and/or subscribe to the specified subjects or wildcards:
nsc edit user --name <n> --allow-pubsub <subject>,...
nsc edit user --name <n> --allow-pub <subject>,...
nsc edit user --name <n> --allow-sub <subject>,...

# Set permissions so that the user cannot publish nor subscribe to the specified subjects or wildcards:
nsc edit user --name <n> --deny-pubsub <subject>,...
nsc edit user --name <n> --deny-pub <subject>,...
nsc edit user --name <n> --deny-sub <subject>,...

# Set subscribe permissions with queue names (separated from subject by space)
# When added this way, the corresponding remove command needs to be presented with the exact same string
nsc edit user --name <n> --deny-sub "<subject> <queue>,..."
nsc edit user --name <n> --allow-sub "<subject> <queue>,..."

# Remove a previously set permissions
nsc edit user --name <n> --rm <subject>,...

# To dynamically allow publishing to reply subjects, this works well for service responders:
nsc edit user --name <n> --allow-pub-response

# A permission to publish a response can be removed after a duration from when
# the message was received:
nsc edit user --name <n> --allow-pub-response --response-ttl 5s

# If the service publishes multiple response messages, you can specify:
nsc edit user --name <n> --allow-pub-response=5
# See 'nsc edit export --response-type --help' to enable multiple
# responses between accounts.

# To remove response settings:
nsc edit user --name <n> --rm-response-perms
`,
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().StringSliceVarP(&params.tags, "tag", "", nil, "add tags for user - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.rmTags, "rm-tag", "", nil, "remove tag - comma separated list or option can be specified multiple times")
	cmd.Flags().StringVarP(&params.name, "name", "n", "", "user name")
	params.AccountContextParams.BindFlags(cmd)
	params.GenericClaimsParams.BindFlags(cmd)
	params.UserPermissionLimits.BindFlags(cmd)
	return cmd
}

func init() {
	editCmd.AddCommand(createEditUserCmd())
}

type EditUserParams struct {
	AccountContextParams
	SignerParams
	GenericClaimsParams
	claim         *jwt.UserClaims
	name          string
	token         string
	credsFilePath string
	UserPermissionLimits
}

func (p *EditUserParams) SetDefaults(ctx ActionCtx) error {
	p.name = NameFlagOrArgument(p.name, ctx)
	if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
		return err
	}
	p.SignerParams.SetDefaults(nkeys.PrefixByteAccount, true, ctx)

	if !InteractiveFlag && ctx.NothingToDo("start", "expiry", "rm", "allow-pub", "allow-sub", "allow-pubsub",
		"deny-pub", "deny-sub", "deny-pubsub", "tag", "rm-tag", "source-network", "rm-source-network", "payload",
		"rm-response-perms", "max-responses", "response-ttl", "allow-pub-response", "bearer", "rm-time", "time", "conn-type",
		"rm-conn-type", "subs", "data") {
		ctx.CurrentCmd().SilenceUsage = false
		return fmt.Errorf("specify an edit option")
	}
	return nil
}

func (p *EditUserParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}

	if p.name == "" {
		p.name, err = PickUser(ctx.StoreCtx(), p.AccountContextParams.Name)
		if err != nil {
			return err
		}
	}

	signers, err := validUserSigners(ctx, p.Name)
	if err != nil {
		return err
	}
	p.SignerParams.SetPrompt("select the key to sign the user")
	return p.SignerParams.SelectFromSigners(ctx, signers)
}

func (p *EditUserParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	if p.name == "" {
		n := ctx.StoreCtx().DefaultUser(p.AccountContextParams.Name)
		if n != nil {
			p.name = *n
		}
	}

	if p.name == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return fmt.Errorf("user name is required")
	}

	if !ctx.StoreCtx().Store.Has(store.Accounts, p.AccountContextParams.Name, store.Users, store.JwtName(p.name)) {
		return fmt.Errorf("user %q not found", p.name)
	}

	p.claim, err = ctx.StoreCtx().Store.ReadUserClaim(p.AccountContextParams.Name, p.name)
	if err != nil {
		return err
	}

	p.UserPermissionLimits.Load(ctx, p.claim.UserPermissionLimits)

	return err
}

func (p *EditUserParams) PostInteractive(ctx ActionCtx) error {
	// FIXME: we won't do interactive on the response params until pub/sub/deny permissions are interactive
	//if err := p.PermissionsParams.Edit(p.claim.Resp != nil); err != nil {
	//	return err
	//}
	if err := p.UserPermissionLimits.PostInteractive(ctx); err != nil {
		return err
	}
	if p.claim.NotBefore > 0 {
		p.GenericClaimsParams.Start = UnixToDate(p.claim.NotBefore)
	}
	if p.claim.Expires > 0 {
		p.GenericClaimsParams.Expiry = UnixToDate(p.claim.Expires)
	}
	if err := p.GenericClaimsParams.Edit(p.claim.Tags); err != nil {
		return err
	}
	return nil
}

func (p *EditUserParams) Validate(ctx ActionCtx) error {
	if err := p.UserPermissionLimits.Validate(ctx); err != nil {
		return err
	}

	if err := p.GenericClaimsParams.Valid(); err != nil {
		return err
	}
	if err := p.SignerParams.ResolveWithPriority(ctx, p.claim.Issuer); err != nil {
		return err
	}

	if ac, err := ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name); err != nil {
		return err
	} else if ac.Limits.DisallowBearer && p.bearer {
		return fmt.Errorf("account disallows bearer token")
	}
	return nil
}

func (p *EditUserParams) Run(ctx ActionCtx) (store.Status, error) {
	r := store.NewDetailedReport(true)
	r.ReportSum = false

	var err error
	if err := p.GenericClaimsParams.Run(ctx, p.claim, r); err != nil {
		return nil, err
	}

	s, err := p.UserPermissionLimits.Run(ctx, &p.claim.UserPermissionLimits)
	if err != nil {
		return nil, err
	}
	if s != nil {
		r.Add(s.Details...)
	}

	// get the account JWT - must have since we resolved the user based on it
	ac, err := ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		return nil, err
	}

	// extract the signer public key
	pk, err := p.signerKP.PublicKey()
	if err != nil {
		return nil, err
	}
	// signer doesn't match - so we set IssuerAccount to the account
	if pk != ac.Subject {
		p.claim.IssuerAccount = ac.Subject
	}

	if err := checkUserForScope(ctx, p.AccountContextParams.Name, p.signerKP, p.claim); err != nil {
		r.AddFromError(err)
		r.AddWarning("user was NOT edited as the edits conflict with signing key scope")
		return r, err
	}

	// we sign
	p.token, err = p.claim.Encode(p.signerKP)
	if err != nil {
		return nil, err
	}

	// if the signer is not allowed, the store will reject
	rs, err := ctx.StoreCtx().Store.StoreClaim([]byte(p.token))
	if rs != nil {
		r.Add(rs)
	}
	if err != nil {
		r.AddFromError(err)
	}
	if rs != nil {
		r.Add(rs)
	}
	ks := ctx.StoreCtx().KeyStore
	if ks.HasPrivateKey(p.claim.Subject) {
		ukp, err := ks.GetKeyPair(p.claim.Subject)
		if err != nil {
			r.AddError("unable to read keypair: %v", err)
		}
		d, err := GenerateConfig(ctx.StoreCtx().Store, p.AccountContextParams.Name, p.name, ukp)
		if err != nil {
			r.AddError("unable to save creds: %v", err)
		} else {
			p.credsFilePath, err = ks.MaybeStoreUserCreds(p.AccountContextParams.Name, p.name, d)
			if err != nil {
				r.AddError("error storing creds: %v", err)
			} else {
				r.AddOK("generated user creds file %#q", AbbrevHomePaths(p.credsFilePath))
			}
		}
	} else {
		r.AddOK("skipped generating creds file - user private key is not available")
	}
	if r.HasNoErrors() {
		r.AddOK("edited user %q", p.name)
	}
	return r, nil
}

const timeFormat = "hh:mm:ss"
const timeLayout = "15:04:05"

type timeSlice []jwt.TimeRange

func (t *timeSlice) Set(val string) error {
	if tk := strings.Split(val, "-"); len(tk) != 2 {
		return fmt.Errorf(`require format: "%s-%s" got "%s"`, timeLayout, timeLayout, val)
	} else if _, err := time.Parse(timeLayout, tk[0]); err != nil {
		return fmt.Errorf(`require format: "%s-%s" could not parse start time "%s"`, timeLayout, timeLayout, tk[0])
	} else if _, err := time.Parse(timeLayout, tk[1]); err != nil {
		return fmt.Errorf(`require format: "%s-%s" could not parse end time "%s"`, timeLayout, timeLayout, tk[1])
	} else {
		*t = append(*t, jwt.TimeRange{Start: tk[0], End: tk[1]})
		return nil
	}
}

func (t *timeSlice) String() string {
	values := make([]string, len(*t))
	for i, r := range *t {
		values[i] = fmt.Sprintf("%s-%s", r.Start, r.End)
	}
	return "[" + strings.Join(values, ",") + "]"
}

func (t *timeSlice) Type() string {
	return "time-ranges"
}

type timeLocale string

func (l *timeLocale) Set(val string) error {
	v, err := time.LoadLocation(val)
	if err == nil {
		*l = timeLocale(v.String())
	}
	return err
}

func (l *timeLocale) String() string {
	return string(*l)
}

func (t *timeLocale) Type() string {
	return "time-locale"
}

type UserPermissionLimits struct {
	PermissionsParams
	bearer      bool
	payload     NumberParams
	maxData     NumberParams
	maxSubs     int64
	rmConnTypes []string
	connTypes   []string
	rmSrc       []string
	src         []string
	locale      timeLocale
	rmTimes     []string
	times       timeSlice
}

func (p *UserPermissionLimits) BindFlags(cmd *cobra.Command) {
	cmd.Flags().VarP(&p.times, "time", "", fmt.Sprintf(`add start-end time range of the form "%s-%s" (option can be specified multiple times)`, timeFormat, timeFormat))
	cmd.Flags().StringSliceVarP(&p.rmTimes, "rm-time", "", nil, fmt.Sprintf(`remove start-end time by start time "%s" (option can be specified multiple times)`, timeFormat))
	cmd.Flags().VarP(&p.locale, "locale", "", "set the locale with which time values are interpreted")
	cmd.Flags().StringSliceVarP(&p.src, "source-network", "", nil, "add source network for connection - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&p.rmSrc, "rm-source-network", "", nil, "remove source network for connection - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&p.connTypes, "conn-type", "", nil, fmt.Sprintf("set allowed connection types: %s %s %s %s %s %s %s - comma separated list or option can be specified multiple times",
		jwt.ConnectionTypeLeafnode, jwt.ConnectionTypeMqtt, jwt.ConnectionTypeStandard, jwt.ConnectionTypeWebsocket, jwt.ConnectionTypeLeafnodeWS, jwt.ConnectionTypeMqttWS, jwt.ConnectionTypeInProcess))
	cmd.Flags().StringSliceVarP(&p.rmConnTypes, "rm-conn-type", "", nil, "remove connection types - comma separated list or option can be specified multiple times")
	cmd.Flags().Int64VarP(&p.maxSubs, "subs", "", -1, "set maximum number of subscriptions (-1 is unlimited)")
	p.maxData = -1
	cmd.Flags().VarP(&p.maxData, "data", "", "set maximum data in bytes for the user (-1 is unlimited)")
	p.payload = -1
	cmd.Flags().VarP(&p.payload, "payload", "", "set maximum message payload in bytes for the account (-1 is unlimited)")
	cmd.Flags().BoolVarP(&p.bearer, "bearer", "", false, "no connect challenge required for user")
	p.PermissionsParams.bindSetFlags(cmd, "permissions")
	p.PermissionsParams.bindRemoveFlags(cmd, "permissions")
}

func (p *UserPermissionLimits) Load(ctx ActionCtx, u jwt.UserPermissionLimits) error {
	if !ctx.CurrentCmd().Flag("payload").Changed {
		p.payload = NumberParams(u.Limits.Payload)
	}
	if !ctx.CurrentCmd().Flag("data").Changed {
		p.maxData = NumberParams(u.Limits.Data)
	}
	if !ctx.CurrentCmd().Flag("subs").Changed {
		p.maxSubs = u.Limits.Subs
	}
	return nil
}

func (p *UserPermissionLimits) PostInteractive(_ ActionCtx) error {
	// FIXME: we won't do interactive on the response params until pub/sub/deny permissions are interactive
	//if err := p.PermissionsParams.Edit(p.claim.Resp != nil); err != nil {
	//	return err
	//}
	if err := p.payload.Edit("max payload (-1 unlimited)"); err != nil {
		return err
	}
	return nil
}

func (p *UserPermissionLimits) Validate(ctx ActionCtx) error {
	connTypes := make([]string, len(p.connTypes))
	for i, k := range p.connTypes {
		u := strings.ToUpper(k)
		switch u {
		case jwt.ConnectionTypeLeafnode, jwt.ConnectionTypeMqtt, jwt.ConnectionTypeStandard,
			jwt.ConnectionTypeWebsocket, jwt.ConnectionTypeLeafnodeWS, jwt.ConnectionTypeMqttWS,
			jwt.ConnectionTypeInProcess:
		default:
			return fmt.Errorf("unknown connection type %s", k)
		}
		connTypes[i] = u
	}
	rmConnTypes := make([]string, len(p.rmConnTypes))
	for i, k := range p.rmConnTypes {
		rmConnTypes[i] = strings.ToUpper(k)
	}
	p.rmConnTypes = rmConnTypes

	if err := p.PermissionsParams.Validate(); err != nil {
		return err
	}

	return nil
}

func (p *UserPermissionLimits) Run(ctx ActionCtx, claim *jwt.UserPermissionLimits) (*store.Report, error) {
	r := store.NewDetailedReport(true)
	r.ReportSum = false

	var err error

	flags := ctx.CurrentCmd().Flags()
	claim.Limits.Payload = p.payload.Int64()
	if flags.Changed("payload") {
		r.AddOK("changed max imports to %d", claim.Limits.Payload)
	}
	claim.Limits.Data = p.maxData.Int64()
	if flags.Changed("data") {
		r.AddOK("changed max data to %d", claim.Limits.Data)
	}
	claim.Limits.Subs = p.maxSubs
	if flags.Changed("subs") {
		r.AddOK("changed max number of subs to %d", claim.Limits.Subs)
	}

	if flags.Changed("bearer") {
		claim.BearerToken = p.bearer
		if flags.Lookup("bearer").DefValue != fmt.Sprint(p.bearer) {
			r.AddOK("changed bearer to %t", p.bearer)
		} else {
			r.AddOK("ignoring change to bearer - value is already %t", p.bearer)
		}
	}

	var connTypes jwt.StringList
	connTypes.Add(claim.AllowedConnectionTypes...)
	connTypes.Add(p.connTypes...)
	for _, v := range p.connTypes {
		r.AddOK("added connection type %s", v)
	}
	connTypes.Remove(p.rmConnTypes...)
	for _, v := range p.rmConnTypes {
		r.AddOK("removed connection type %s", v)
	}
	claim.AllowedConnectionTypes = connTypes

	var srcList jwt.CIDRList
	srcList.Add(claim.Src...)
	srcList.Add(p.src...)
	for _, v := range p.src {
		r.AddOK("added src network %s", v)
	}
	srcList.Remove(p.rmSrc...)
	for _, v := range p.rmSrc {
		r.AddOK("removed src network %s", v)
	}
	sort.Strings(srcList)
	claim.Src = srcList

	if flags.Changed("locale") {
		claim.Locale = p.locale.String()
	}
	for _, v := range p.times {
		r.AddOK("added time range %s-%s", v.Start, v.End)
		claim.Times = append(claim.Times, v)
	}
	for _, vDel := range p.rmTimes {
		for i, v := range claim.Times {
			if v.Start == vDel {
				r.AddOK("removed time range %s-%s", v.Start, v.End)
				a := claim.Times
				// Remove the element at index i from a.
				copy(a[i:], a[i+1:])          // Shift a[i+1:] left one index.
				a[len(a)-1] = jwt.TimeRange{} // Erase last element (write zero value).
				claim.Times = a[:len(a)-1]    // Truncate slice.
				break
			}
		}
	}

	s, err := p.PermissionsParams.Run(&claim.Permissions, ctx)
	if err != nil {
		return nil, err
	}
	if s != nil {
		r.Add(s.Details...)
	}

	return r, nil
}
