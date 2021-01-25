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
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func CreateAddUserCmd() *cobra.Command {
	var params AddUserParams
	cmd := &cobra.Command{
		Use:          "user",
		Short:        "Add an user to the account",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		Example: `# Add user with a previously generated public key:
nsc add user --name <n> --public-key <nkey>
# Note: that unless you specify the seed, the key won't be stored in the keyring.'

# Set permissions so that the user can publish and/or subscribe to the specified subjects or wildcards:
nsc add user --name <n> --allow-pubsub <subject>,...
nsc add user --name <n> --allow-pub <subject>,...
nsc add user --name <n> --allow-sub <subject>,...

# Set permissions so that the user cannot publish nor subscribe to the specified subjects or wildcards:
nsc add user --name <n> --deny-pubsub <subject>,...
nsc add user --name <n> --deny-pub <subject>,...
nsc add user --name <n> --deny-sub <subject>,...

# Set subscribe permissions with queue names (separated from subject by space)
# When added this way, the corresponding remove command needs to be presented with the exact same string
nsc add user --name <n> --deny-sub "<subject> <queue>,..."
nsc add user --name <n> --allow-sub "<subject> <queue>,..."

# To dynamically allow publishing to reply subjects, this works well for service responders:
nsc add user --name <n> --allow-pub-response

# A permission to publish a response can be removed after a duration from when 
# the message was received:
nsc add user --name <n> --allow-pub-response --response-ttl 5s

# If the service publishes multiple response messages, you can specify:
nsc add user --name <n> --allow-pub-response=5
# See 'nsc edit export --response-type --help' to enable multiple
# responses between accounts
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}

	cmd.Flags().StringSliceVarP(&params.tags, "tag", "", nil, "tags for user - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.src, "source-network", "", nil, "source network for connection - comma separated list or option can be specified multiple times")

	cmd.Flags().StringVarP(&params.userName, "name", "n", "", "name to assign the user")
	cmd.Flags().StringVarP(&params.pkOrPath, "public-key", "k", "", "public key identifying the user")

	cmd.Flags().BoolVarP(&params.bearer, "bearer", "", false, "no connect challenge required for user")

	params.TimeParams.BindFlags(cmd)
	params.AccountContextParams.BindFlags(cmd)
	params.PermissionsParams.bindSetFlags(cmd, "permissions")

	return cmd
}

func init() {
	addCmd.AddCommand(CreateAddUserCmd())
}

type AddUserParams struct {
	AccountContextParams
	SignerParams
	TimeParams
	PermissionsParams
	src           []string
	tags          []string
	credsFilePath string
	bearer        bool
	userName      string
	pkOrPath      string
	kp            nkeys.KeyPair
}

func (p *AddUserParams) SetDefaults(ctx ActionCtx) error {
	p.userName = NameFlagOrArgument(p.userName, ctx)
	if p.userName == "*" {
		p.userName = GetRandomName(0)
	}
	if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
		return err
	}
	p.SignerParams.SetDefaults(nkeys.PrefixByteAccount, true, ctx)

	return nil
}

func (p *AddUserParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}

	p.userName, err = cli.Prompt("user name", p.userName, cli.NewLengthValidator(1))
	if err != nil {
		return err
	}

	ok, err := cli.Confirm("generate an user nkey", true)
	if err != nil {
		return err
	}
	if !ok {
		p.pkOrPath, err = cli.Prompt("path to an user nkey or nkey", p.pkOrPath, cli.Val(func(v string) error {
			nk, err := store.ResolveKey(v)
			if err != nil {
				return err
			}
			if nk == nil {
				return fmt.Errorf("a key is required")
			}
			t, err := store.KeyType(nk)
			if err != nil {
				return err
			}
			if t != nkeys.PrefixByteUser {
				return errors.New("specified key is not a valid for an user")
			}
			return nil
		}))
		if err != nil {
			return err
		}
	}

	// FIXME: we won't do interactive on the response params until pub/sub/deny permissions are interactive
	//if err := p.PermissionsParams.Edit(false); err != nil {
	//	return err
	//}

	if err = p.TimeParams.Edit(); err != nil {
		return err
	}

	signers, err := validUserSigners(ctx, p.Name)
	if err != nil {
		return err
	}
	p.SignerParams.SetPrompt("select the key to sign the user")
	return p.SignerParams.SelectFromSigners(ctx, signers)
}

func (p *AddUserParams) Load(_ ActionCtx) error {
	return nil
}

func validUserSigners(ctx ActionCtx, accName string) ([]string, error) {
	ac, err := ctx.StoreCtx().Store.ReadAccountClaim(accName)
	if err != nil {
		return nil, err
	}
	var signers []string
	if ctx.StoreCtx().KeyStore.HasPrivateKey(ac.Subject) {
		signers = append(signers, ac.Subject)
	}
	for signingKey := range ac.SigningKeys {
		if ctx.StoreCtx().KeyStore.HasPrivateKey(signingKey) {
			signers = append(signers, signingKey)
		}
	}
	return signers, nil
}

func (p *AddUserParams) PostInteractive(_ ActionCtx) error {
	return nil
}

func (p *AddUserParams) Validate(ctx ActionCtx) error {
	var err error
	if p.userName == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return fmt.Errorf("user name is required")
	}

	if p.userName == "*" {
		p.userName = GetRandomName(0)
	}

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	if err = p.SignerParams.Resolve(ctx); err != nil {
		return err
	}

	if err := p.TimeParams.Validate(); err != nil {
		return err
	}

	if err := p.PermissionsParams.Validate(); err != nil {
		return err
	}

	if p.pkOrPath != "" {
		p.kp, err = store.ResolveKey(p.pkOrPath)
		if err != nil {
			return err
		}
		if !store.KeyPairTypeOk(nkeys.PrefixByteUser, p.kp) {
			return errors.New("invalid user key")
		}
	} else {
		p.kp, err = nkeys.CreatePair(nkeys.PrefixByteUser)
		if err != nil {
			return err
		}
	}

	s := ctx.StoreCtx().Store
	if s.Has(store.Accounts, ctx.StoreCtx().Account.Name, store.Users, store.JwtName(p.userName)) {
		return fmt.Errorf("the user %q already exists", p.userName)
	}

	return nil
}

func (p *AddUserParams) Run(ctx ActionCtx) (store.Status, error) {
	r := store.NewDetailedReport(false)
	uc, err := p.generateUserClaim(ctx, r)
	if err != nil {
		return nil, err
	}

	token, err := uc.Encode(p.signerKP)
	if err != nil {
		return nil, err
	}

	st, err := ctx.StoreCtx().Store.StoreClaim([]byte(token))
	if err != nil {
		r.AddFromError(err)
		return st, err
	}
	if st != nil {
		r.Add(st)
	}

	// store the key
	if p.pkOrPath == "" {
		ks := ctx.StoreCtx()
		var err error
		if p.pkOrPath, err = ks.KeyStore.Store(p.kp); err != nil {
			r.AddFromError(err)
			return r, err
		}
		r.AddOK("generated and stored user key %q", uc.Subject)
	}

	pk := uc.Subject
	// if they gave us a seed, it stored - try to get it
	ks := ctx.StoreCtx().KeyStore
	if ks.HasPrivateKey(pk) {
		// we may have it - but the key we got is possibly a pub only - resolve it from the store.
		p.kp, _ = ks.GetKeyPair(pk)
		d, err := GenerateConfig(ctx.StoreCtx().Store, p.AccountContextParams.Name, p.userName, p.kp)
		if err != nil {
			r.AddError("unable to save creds: %v", err)
		} else {
			p.credsFilePath, err = ks.MaybeStoreUserCreds(p.AccountContextParams.Name, p.userName, d)
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
		r.AddOK("added user %q to account %q", p.userName, p.AccountContextParams.Name)
	}
	return r, nil
}

func (p *AddUserParams) generateUserClaim(ctx ActionCtx, r *store.Report) (*jwt.UserClaims, error) {
	pub, err := p.kp.PublicKey()
	if err != nil {
		return nil, err
	}
	uc := jwt.NewUserClaims(pub)
	uc.Name = p.userName

	spk, err := p.signerKP.PublicKey()
	if err != nil {
		return nil, err
	}
	if ctx.StoreCtx().Account.PublicKey != spk {
		uc.IssuerAccount = ctx.StoreCtx().Account.PublicKey
	}

	if p.TimeParams.IsStartChanged() {
		uc.NotBefore, _ = p.TimeParams.StartDate()
	}

	if p.TimeParams.IsExpiryChanged() {
		uc.Expires, _ = p.TimeParams.ExpiryDate()
	}

	if s, err := p.PermissionsParams.Run(&uc.Permissions, ctx); err != nil {
		return nil, err
	} else if s != nil {
		r.Add(s.Details...)
	}

	uc.Tags.Add(p.tags...)
	sort.Strings(uc.Tags)

	uc.BearerToken = p.bearer
	return uc, nil
}

type PermissionsParams struct {
	respTTL     string
	respMax     int
	rmResp      bool
	allowPubs   []string
	allowPubsub []string
	allowSubs   []string
	denyPubs    []string
	denyPubsub  []string
	denySubs    []string
	rmPerms     []string
}

func (p *PermissionsParams) bindSetFlags(cmd *cobra.Command, typeName string) {
	cmd.Flags().StringVarP(&p.respTTL, "response-ttl", "", "", fmt.Sprintf("the amount of time the %s is valid (global) - [#ms(millis) | #s(econds) | m(inutes) | h(ours)] - Default is no time limit.", typeName))

	cmd.Flags().IntVarP(&p.respMax, "allow-pub-response", "", 0, fmt.Sprintf("%s to limit how often a client can publish to reply subjects [with an optional count, --allow-pub-response=n] (global)", typeName))
	cmd.Flag("allow-pub-response").NoOptDefVal = "1"

	cmd.Flags().IntVarP(&p.respMax, "max-responses", "", 0, fmt.Sprintf("%s to limit how ofthen a client can publish to reply subjects [with an optional count] (global)", typeName))
	cmd.Flag("max-responses").Hidden = true
	cmd.Flag("max-responses").Deprecated = "use --allow-pub-response or --allow-pub-response=n"

	cmd.Flags().StringSliceVarP(&p.allowPubs, "allow-pub", "", nil, fmt.Sprintf("add publish %s - comma separated list or option can be specified multiple times", typeName))
	cmd.Flags().StringSliceVarP(&p.allowPubsub, "allow-pubsub", "", nil, fmt.Sprintf("add publish and subscribe %s - comma separated list or option can be specified multiple times", typeName))
	cmd.Flags().StringSliceVarP(&p.allowSubs, "allow-sub", "", nil, fmt.Sprintf("add subscribe %s - comma separated list or option can be specified multiple times", typeName))
	cmd.Flags().StringSliceVarP(&p.denyPubs, "deny-pub", "", nil, fmt.Sprintf("add deny publish %s - comma separated list or option can be specified multiple times", typeName))
	cmd.Flags().StringSliceVarP(&p.denyPubsub, "deny-pubsub", "", nil, fmt.Sprintf("add deny publish and subscribe %s - comma separated list or option can be specified multiple times", typeName))
	cmd.Flags().StringSliceVarP(&p.denySubs, "deny-sub", "", nil, fmt.Sprintf("add deny subscribe %s - comma separated list or option can be specified multiple times", typeName))
}

func (p *PermissionsParams) bindRemoveFlags(cmd *cobra.Command, typeName string) {
	cmd.Flags().BoolVarP(&p.rmResp, "rm-response-perms", "", false, fmt.Sprintf("remove response settings from %s", typeName))
	cmd.Flags().StringSliceVarP(&p.rmPerms, "rm", "", nil, fmt.Sprintf("remove publish/subscribe and deny %s - comma separated list or option can be specified multiple times", typeName))
}

func (p *PermissionsParams) maxResponseValidator(s string) error {
	_, err := p.parseMaxResponse(s)
	return err
}

func (p *PermissionsParams) parseMaxResponse(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	return strconv.Atoi(s)
}

func (p *PermissionsParams) ttlValidator(s string) error {
	_, err := p.parseTTL(s)
	return err
}

func (p *PermissionsParams) parseTTL(s string) (time.Duration, error) {
	if s == "" {
		return time.Duration(0), nil
	}
	return time.ParseDuration(s)
}

func (p *PermissionsParams) Edit(hasPerm bool) error {
	verb := "Set"
	if hasPerm {
		verb = "Edit"
	}
	ok, err := cli.Confirm(fmt.Sprintf("%s response permissions?", verb), false)
	if err != nil {
		return err
	}
	if ok {
		if hasPerm {
			p.rmResp, err = cli.Confirm("delete response permission", p.rmResp)
			if err != nil {
				return err
			}
		}
		if !p.rmResp {
			s, err := cli.Prompt("Max number of responses", fmt.Sprintf("%d", p.respMax), cli.Val(p.maxResponseValidator))
			if err != nil {
				return err
			}
			p.respMax, _ = p.parseMaxResponse(s)
			p.respTTL, err = cli.Prompt("Response TTL", p.respTTL, cli.Val(p.ttlValidator))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *PermissionsParams) Validate() error {
	if err := p.ttlValidator(p.respTTL); err != nil {
		return err
	}
	for _, v := range [][]string{p.allowPubs, p.allowPubsub, p.denyPubs, p.denyPubsub} {
		for _, sub := range v {
			if strings.Contains(sub, " ") {
				return fmt.Errorf("publish permission subject %q contains illegal space", sub)
			}
		}
	}
	for _, v := range [][]string{p.allowSubs, p.denySubs} {
		for _, sub := range v {
			if strings.Count(sub, " ") > 1 {
				return fmt.Errorf("subscribe permission subject %q can at most contain one space", sub)
			}
		}
	}

	return nil
}

func (p *PermissionsParams) Run(perms *jwt.Permissions, ctx ActionCtx) (*store.Report, error) {
	r := store.NewDetailedReport(true)
	if p.rmResp {
		perms.Resp = nil
		r.AddOK("removed response permissions")
		return r, nil
	}

	if ctx.CurrentCmd().Flag("max-responses").Changed || p.respMax != 0 {
		if perms.Resp == nil {
			perms.Resp = &jwt.ResponsePermission{}
		}
		perms.Resp.MaxMsgs = p.respMax
		r.AddOK("set max responses to %d", p.respMax)
	}

	if p.respTTL != "" {
		v, err := p.parseTTL(p.respTTL)
		if err != nil {
			return nil, err
		}
		if perms.Resp == nil {
			perms.Resp = &jwt.ResponsePermission{}
		}
		perms.Resp.Expires = v
		r.AddOK("set response ttl to %v", v)
	}

	var ap []string
	perms.Pub.Allow.Add(p.allowPubs...)
	ap = append(ap, p.allowPubs...)
	perms.Pub.Allow.Add(p.allowPubsub...)
	ap = append(ap, p.allowPubsub...)
	for _, v := range ap {
		r.AddOK("added pub pub %q", v)
	}
	perms.Pub.Allow.Remove(p.rmPerms...)
	for _, v := range p.rmPerms {
		r.AddOK("removed pub %q", v)
	}
	sort.Strings(perms.Pub.Allow)

	var dp []string
	perms.Pub.Deny.Add(p.denyPubs...)
	dp = append(dp, p.denyPubs...)
	perms.Pub.Deny.Add(p.denyPubsub...)
	dp = append(dp, p.denyPubsub...)
	for _, v := range dp {
		r.AddOK("added deny pub %q", v)
	}
	perms.Pub.Deny.Remove(p.rmPerms...)
	for _, v := range p.rmPerms {
		r.AddOK("removed deny pub %q", v)
	}
	sort.Strings(perms.Pub.Deny)

	var sa []string
	perms.Sub.Allow.Add(p.allowSubs...)
	sa = append(sa, p.allowSubs...)
	perms.Sub.Allow.Add(p.allowPubsub...)
	sa = append(sa, p.allowPubsub...)
	for _, v := range sa {
		r.AddOK("added sub %q", v)
	}
	perms.Sub.Allow.Remove(p.rmPerms...)
	for _, v := range p.rmPerms {
		r.AddOK("removed sub %q", v)
	}
	sort.Strings(perms.Sub.Allow)

	perms.Sub.Deny.Add(p.denySubs...)
	perms.Sub.Deny.Add(p.denyPubsub...)
	perms.Sub.Deny.Remove(p.rmPerms...)
	sort.Strings(perms.Sub.Deny)
	return r, nil
}
