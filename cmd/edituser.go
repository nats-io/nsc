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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nsc/cli"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createEditUserCmd() *cobra.Command {
	var params EditUserParams
	cmd := &cobra.Command{
		Use:          "user",
		Short:        "Edit an user",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}

			s, err := GetStore()
			if err == nil {
				ctx, err := s.GetContext()
				if err == nil {
					creds := ctx.KeyStore.GetUserCredsPath(params.AccountContextParams.Name, params.name)
					if creds != "" {
						fmt.Printf("Updated user creds file %q\n", AbbrevHomePaths(creds))
					}
				}
			}

			cmd.Printf("Success! - edited user %q in account %q\n", params.name, params.AccountContextParams.Name)
			cmd.Println()

			d, err := jwt.DecorateJWT(params.token)
			if err != nil {
				return err
			}
			Write("--", d)

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

			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&params.remove, "rm", "", nil, "remove publish/subscribe and deny permissions - comma separated list or option can be specified multiple times")

	cmd.Flags().StringSliceVarP(&params.allowPubs, "allow-pub", "", nil, "add publish permissions - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.allowPubsub, "allow-pubsub", "", nil, "add publish and subscribe permissions - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.allowSubs, "allow-sub", "", nil, "add subscribe permissions - comma separated list or option can be specified multiple times")

	cmd.Flags().StringSliceVarP(&params.denyPubs, "deny-pub", "", nil, "add deny publish permissions - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.denyPubsub, "deny-pubsub", "", nil, "add deny publish and subscribe permissions - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.denySubs, "deny-sub", "", nil, "add deny subscribe permissions - comma separated list or option can be specified multiple times")

	cmd.Flags().StringVarP(&params.respTTL, "response-ttl", "", "", "max ttl for responding to requests (global to all requests for user)")
	cmd.Flags().StringVarP(&params.respMax, "max-responses", "", "", "max number of responses for a request (global to all requests for the user)")
	cmd.Flags().BoolVarP(&params.rmResp, "rm-response", "", false, "remove response settings")

	cmd.Flags().StringSliceVarP(&params.tags, "tag", "", nil, "add tags for user - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.rmTags, "rm-tag", "", nil, "remove tag - comma separated list or option can be specified multiple times")

	cmd.Flags().StringSliceVarP(&params.src, "source-network", "", nil, "add source network for connection - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.rmSrc, "rm-source-network", "", nil, "remove source network for connection - comma separated list or option can be specified multiple times")

	cmd.Flags().Int64VarP(&params.payload.Number, "payload", "", -1, "set maximum message payload in bytes for the account (-1 is unlimited)")

	cmd.Flags().StringVarP(&params.name, "name", "n", "", "user name")

	cmd.Flags().StringVarP(&params.out, "output-file", "o", "", "output file '--' is stdout")

	params.AccountContextParams.BindFlags(cmd)
	params.GenericClaimsParams.BindFlags(cmd)

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
	out           string
	credsFilePath string

	allowPubs   []string
	allowPubsub []string
	allowSubs   []string
	denyPubs    []string
	denyPubsub  []string
	denySubs    []string
	remove      []string
	rmSrc       []string
	src         []string
	payload     DataParams
	respTTL     string
	respMax     string
	rmResp      bool
}

func (p *EditUserParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.SetDefaults(ctx)
	p.SignerParams.SetDefaults(nkeys.PrefixByteAccount, true, ctx)

	if !InteractiveFlag && ctx.NothingToDo("start", "expiry", "rm", "allow-pub", "allow-sub", "allow-pubsub",
		"deny-pub", "deny-sub", "deny-pubsub", "tag", "rm-tag", "source-network", "rm-source-network", "payload",
		"rm-response", "max-responses", "response-ttl") {
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

	return nil
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
		p.payload.Number = p.claim.Limits.Payload
	}

	return err
}

func (p *EditUserParams) PostInteractive(ctx ActionCtx) error {
	var err error
	var ok bool
	if p.claim.Resp == nil {
		ok, err = cli.PromptYN("Set response permissions")
		if err != nil {
			return err
		}
	} else {
		ok = true
	}
	if p.claim.Resp != nil {
		p.rmResp, err = cli.PromptBoolean("Delete response permissions", p.rmResp)
	}
	if ok && !p.rmResp {
		p.respMax, err = cli.Prompt("Number of max responses", p.respMax, true, func(v string) error {
			_, err := strconv.ParseInt(v, 10, 32)
			if err != nil {
				return err
			}
			return nil
		})
		p.respTTL, err = cli.Prompt("Response TTL duration", p.respTTL, true, func(v string) error {
			_, err := time.ParseDuration(v)
			if err != nil {
				return err
			}
			return nil
		})
	}

	if err := p.payload.Edit("max payload (-1 unlimited)"); err != nil {
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

	if err = p.SignerParams.Edit(ctx); err != nil {
		return err
	}

	return nil
}

func (p *EditUserParams) Validate(ctx ActionCtx) error {
	var err error

	_, err = p.payload.NumberValue()
	if err != nil {
		return fmt.Errorf("error parsing %s: %s", "payload", p.payload.Value)
	}
	if err = p.GenericClaimsParams.Valid(); err != nil {
		return err
	}
	if err = p.SignerParams.Resolve(ctx); err != nil {
		return err
	}
	if err = p.payload.Valid(); err != nil {
		return err
	}

	if !p.rmResp {
		if p.respMax != "" {
			_, err := strconv.ParseInt(p.respMax, 10, 32)
			if err != nil {
				return err
			}
		}

		if p.respTTL != "" {
			_, err := time.ParseDuration(p.respTTL)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *EditUserParams) Run(ctx ActionCtx) error {
	var err error
	p.GenericClaimsParams.Run(ctx, p.claim)

	p.claim.Permissions.Pub.Allow.Add(p.allowPubs...)
	p.claim.Permissions.Pub.Allow.Add(p.allowPubsub...)
	p.claim.Permissions.Pub.Allow.Remove(p.remove...)
	sort.Strings(p.claim.Pub.Allow)

	p.claim.Permissions.Pub.Deny.Add(p.denyPubs...)
	p.claim.Permissions.Pub.Deny.Add(p.denyPubsub...)
	p.claim.Permissions.Pub.Deny.Remove(p.remove...)
	sort.Strings(p.claim.Permissions.Pub.Deny)

	p.claim.Permissions.Sub.Allow.Add(p.allowSubs...)
	p.claim.Permissions.Sub.Allow.Add(p.allowPubsub...)
	p.claim.Permissions.Sub.Allow.Remove(p.remove...)
	sort.Strings(p.claim.Permissions.Sub.Allow)

	p.claim.Permissions.Sub.Deny.Add(p.denySubs...)
	p.claim.Permissions.Sub.Deny.Add(p.denyPubsub...)
	p.claim.Permissions.Sub.Deny.Remove(p.remove...)
	sort.Strings(p.claim.Permissions.Sub.Deny)

	p.claim.Limits.Payload = p.payload.Number

	sort.Strings(p.claim.Tags)

	src := strings.Split(p.claim.Src, ",")
	var srcList jwt.StringList
	srcList.Add(src...)
	srcList.Add(p.src...)
	srcList.Remove(p.rmSrc...)
	sort.Strings(srcList)
	p.claim.Src = strings.Join(srcList, ",")

	if p.rmResp && p.claim.Resp != nil {
		p.claim.Resp = nil
	} else {
		if p.respMax != "" {
			v, err := strconv.ParseInt(p.respMax, 10, 32)
			if err != nil {
				return err
			}
			if p.claim.Resp == nil {
				p.claim.Resp = &jwt.ResponsePermission{Expires: time.Millisecond * 5000}
			}
			p.claim.Resp.MaxMsgs = int(v)
		}

		if p.respTTL != "" {
			v, err := time.ParseDuration(p.respTTL)
			if err != nil {
				return err
			}
			if p.claim.Resp == nil {
				p.claim.Resp = &jwt.ResponsePermission{MaxMsgs: 1}
			}
			p.claim.Resp.Expires = v
		}
	}

	// get the account JWT - must have since we resolved the user based on it
	ac, err := ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		return err
	}

	// extract the signer public key
	pk, err := p.signerKP.PublicKey()
	if err != nil {
		return err
	}
	// signer doesn't match - so we set IssuerAccount to the account
	if pk != ac.Subject {
		p.claim.IssuerAccount = ac.Subject
	}

	// we sign
	p.token, err = p.claim.Encode(p.signerKP)
	if err != nil {
		return err
	}

	// if the signer is not allowed, the store will reject
	if err := ctx.StoreCtx().Store.StoreClaim([]byte(p.token)); err != nil {
		return err
	}

	// FIXME: super hack
	ks := ctx.StoreCtx().KeyStore
	ukp, err := ks.GetKeyPair(p.claim.Subject)
	if err != nil {
		ctx.CurrentCmd().Printf("unable to save creds: %v", err)
	}
	if ukp == nil {
		ctx.CurrentCmd().Println("unable to save creds - user key not found")
	}
	if ukp != nil {
		d, err := GenerateConfig(ctx.StoreCtx().Store, p.AccountContextParams.Name, p.name, ukp)
		if err != nil {
			ctx.CurrentCmd().Printf("unable to save creds: %v", err)
		} else {
			p.credsFilePath, err = ks.MaybeStoreUserCreds(p.AccountContextParams.Name, p.name, d)
			if err != nil {
				ctx.CurrentCmd().Println(err.Error())
			}
		}
	}

	return nil
}
