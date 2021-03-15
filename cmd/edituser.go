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
	"sort"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
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

	cmd.Flags().VarP(&params.times, "time", "", fmt.Sprintf(`add start-end time range of the form "%s-%s" (option can be specified multiple times)`, timeFormat, timeFormat))
	cmd.Flags().StringSliceVarP(&params.rmTimes, "rm-time", "", nil, fmt.Sprintf(`remove start-end time by start time "%s" (option can be specified multiple times)`, timeFormat))
	cmd.Flags().VarP(&params.locale, "locale", "", "set the locale with which time values are interpreted")

	cmd.Flags().StringSliceVarP(&params.tags, "tag", "", nil, "add tags for user - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.rmTags, "rm-tag", "", nil, "remove tag - comma separated list or option can be specified multiple times")

	cmd.Flags().StringSliceVarP(&params.src, "source-network", "", nil, "add source network for connection - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.rmSrc, "rm-source-network", "", nil, "remove source network for connection - comma separated list or option can be specified multiple times")

	cmd.Flags().StringVarP(&params.payload.Value, "payload", "", "-1", "set maximum message payload in bytes for the account (-1 is unlimited)")

	cmd.Flags().StringVarP(&params.name, "name", "n", "", "user name")
	cmd.Flags().StringSliceVarP(&params.connTypes, "conn-type", "", nil, fmt.Sprintf("add connection types: %s %s %s %s - comma separated list or option can be specified multiple times",
		jwt.ConnectionTypeLeafnode, jwt.ConnectionTypeMqtt, jwt.ConnectionTypeStandard, jwt.ConnectionTypeWebsocket))
	cmd.Flags().StringSliceVarP(&params.rmConnTypes, "rm-conn-type", "", nil, "remove connection types - comma separated list or option can be specified multiple times")

	cmd.Flags().BoolVarP(&params.bearer, "bearer", "", false, "no connect challenge required for user")

	cmd.Flags().Int64VarP(&params.maxSubs, "subs", "", -1, "set maximum number of subscriptions (-1 is unlimited)")
	cmd.Flags().StringVarP(&params.maxData.Value, "data", "", "-1", "set maximum data in bytes for the user (-1 is unlimited)")

	params.AccountContextParams.BindFlags(cmd)
	params.GenericClaimsParams.BindFlags(cmd)
	params.PermissionsParams.bindSetFlags(cmd, "permissions")
	params.PermissionsParams.bindRemoveFlags(cmd, "permissions")

	return cmd
}

func init() {
	editCmd.AddCommand(createEditUserCmd())
}

type EditUserParams struct {
	AccountContextParams
	SignerParams
	GenericClaimsParams
	PermissionsParams
	claim         *jwt.UserClaims
	name          string
	token         string
	credsFilePath string

	bearer      bool
	connTypes   []string
	locale      timeLocale
	maxData     DataParams
	maxSubs     int64
	payload     DataParams
	rmConnTypes []string
	rmSrc       []string
	rmTimes     []string
	src         []string
	times       timeSlice
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
		p.name, err = ctx.StoreCtx().PickUser(p.AccountContextParams.Name)
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

	if !ctx.CurrentCmd().Flag("payload").Changed {
		p.payload.Value = fmt.Sprintf("%d", p.claim.Limits.Payload)
	}
	if !ctx.CurrentCmd().Flag("data").Changed {
		p.maxData.Value = fmt.Sprintf("%d", p.claim.Limits.Data)
	}
	if !ctx.CurrentCmd().Flag("subs").Changed {
		p.maxSubs = p.claim.Limits.Subs
	}

	return err
}

func (p *EditUserParams) PostInteractive(_ ActionCtx) error {
	// FIXME: we won't do interactive on the response params until pub/sub/deny permissions are interactive
	//if err := p.PermissionsParams.Edit(p.claim.Resp != nil); err != nil {
	//	return err
	//}
	if err := p.payload.Edit("max payload (-1 unlimited)"); err != nil {
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
	var err error

	connTypes := make([]string, len(p.connTypes))
	for i, k := range p.connTypes {
		u := strings.ToUpper(k)
		switch u {
		case jwt.ConnectionTypeLeafnode, jwt.ConnectionTypeMqtt, jwt.ConnectionTypeStandard, jwt.ConnectionTypeWebsocket:
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

	_, err = p.payload.NumberValue()
	if err != nil {
		return fmt.Errorf("error parsing %s: %s", "payload", p.payload.Value)
	}
	if _, err := p.maxData.NumberValue(); err != nil {
		return fmt.Errorf("error parsing %s: %s", "data", p.payload.Value)
	}
	if err = p.GenericClaimsParams.Valid(); err != nil {
		return err
	}
	if err = p.SignerParams.ResolveWithPriority(ctx, p.claim.Issuer); err != nil {
		return err
	}
	if err = p.payload.Valid(); err != nil {
		return err
	}
	if err = p.maxData.Valid(); err != nil {
		return err
	}
	if err := p.PermissionsParams.Validate(); err != nil {
		return err
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

	flags := ctx.CurrentCmd().Flags()
	p.claim.Limits.Payload, _ = p.payload.NumberValue()
	if flags.Changed("payload") {
		r.AddOK("changed max imports to %d", p.claim.Limits.Payload)
	}
	p.claim.Limits.Data, _ = p.maxData.NumberValue()
	if flags.Changed("data") {
		r.AddOK("changed max data to %d", p.claim.Limits.Data)
	}
	p.claim.Limits.Subs = p.maxSubs
	if flags.Changed("subs") {
		r.AddOK("changed max number of subs to %d", p.claim.Limits.Subs)
	}

	if flags.Changed("bearer") {
		p.claim.BearerToken = p.bearer
		r.AddOK("changed bearer to %t", p.bearer)
	}

	var connTypes jwt.StringList
	connTypes.Add(p.claim.AllowedConnectionTypes...)
	connTypes.Add(p.connTypes...)
	for _, v := range p.connTypes {
		r.AddOK("added connection type %s", v)
	}
	connTypes.Remove(p.rmConnTypes...)
	for _, v := range p.rmConnTypes {
		r.AddOK("removed connection type %s", v)
	}
	p.claim.AllowedConnectionTypes = connTypes

	var srcList jwt.CIDRList
	srcList.Add(p.claim.Src...)
	srcList.Add(p.src...)
	for _, v := range p.src {
		r.AddOK("added src network %s", v)
	}
	srcList.Remove(p.rmSrc...)
	for _, v := range p.rmSrc {
		r.AddOK("removed src network %s", v)
	}
	sort.Strings(srcList)
	p.claim.Src = srcList

	if flags.Changed("locale") {
		p.claim.Locale = p.locale.String()
	}
	for _, v := range p.times {
		r.AddOK("added time range %s-%s", v.Start, v.End)
		p.claim.Times = append(p.claim.Times, v)
	}
	for _, vDel := range p.rmTimes {
		for i, v := range p.claim.Times {
			if v.Start == vDel {
				r.AddOK("removed time range %s-%s", v.Start, v.End)
				a := p.claim.Times
				// Remove the element at index i from a.
				copy(a[i:], a[i+1:])          // Shift a[i+1:] left one index.
				a[len(a)-1] = jwt.TimeRange{} // Erase last element (write zero value).
				p.claim.Times = a[:len(a)-1]  // Truncate slice.
				break
			}
		}
	}

	s, err := p.PermissionsParams.Run(&p.claim.Permissions, ctx)
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
