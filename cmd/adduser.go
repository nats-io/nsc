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
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nsc/cli"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/spf13/cobra"
)

func CreateAddUserCmd() *cobra.Command {
	var params AddUserParams
	cmd := &cobra.Command{
		Use:          "user",
		Short:        "Add an user to the account",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		Example:      params.longHelp(),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}

			if params.generated && !QuietMode() {
				cmd.Printf("Generated user key - private key stored %q\n", AbbrevHomePaths(params.keyPath))
				s, err := GetStore()
				if err == nil {
					ctx, err := s.GetContext()
					if err == nil {
						fp := ctx.KeyStore.GetUserCredsPath(params.AccountContextParams.Name, params.name)
						if fp != "" {
							cmd.Printf("Generated user creds file %q\n", AbbrevHomePaths(fp))
						}
					}
				}
			}

			if !QuietMode() {
				cmd.Printf("Success! - added user %q to %q\n", params.name, params.AccountContextParams.Name)
			}

			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&params.allowPubs, "allow-pub", "", nil, "publish permissions - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.allowPubsub, "allow-pubsub", "", nil, "publish and subscribe permissions - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.allowSubs, "allow-sub", "", nil, "subscribe permissions - comma separated list or option can be specified multiple times")

	cmd.Flags().StringSliceVarP(&params.denyPubs, "deny-pub", "", nil, "deny publish permissions - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.denyPubsub, "deny-pubsub", "", nil, "deny publish and subscribe permissions - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.denySubs, "deny-sub", "", nil, "deny subscribe permissions - comma separated list or option can be specified multiple times")

	cmd.Flags().StringVarP(&params.respTTL, "response-permission-ttl", "", "", "max response permission ttl for responding to requests (global to all requests for user)")
	cmd.Flags().StringVarP(&params.respMax, "max-responses", "", "", "max number of responses for a request (global to all requests for the user)")

	cmd.Flags().StringSliceVarP(&params.tags, "tag", "", nil, "tags for user - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.src, "source-network", "", nil, "source network for connection - comma separated list or option can be specified multiple times")

	cmd.Flags().StringVarP(&params.name, "name", "n", "", "name to assign the user")
	cmd.Flags().StringVarP(&params.keyPath, "public-key", "k", "", "public key identifying the user")

	cmd.Flags().StringVarP(&params.out, "output-file", "o", "", "output file '--' is stdout")

	params.TimeParams.BindFlags(cmd)
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	addCmd.AddCommand(CreateAddUserCmd())
}

type AddUserParams struct {
	AccountContextParams
	SignerParams
	Entity
	TimeParams
	respTTL       string
	respMax       string
	allowPubs     []string
	allowPubsub   []string
	allowSubs     []string
	denyPubs      []string
	denyPubsub    []string
	denySubs      []string
	out           string
	src           []string
	tags          []string
	credsFilePath string
}

func (p *AddUserParams) longHelp() string {
	s := `toolName add user -i
toolName add user --name u --deny-pubsub "bar.>"
toolName add user --name u --tag test,service_a`

	return strings.Replace(s, "toolName", GetToolName(), -1)
}

func (p *AddUserParams) SetDefaults(ctx ActionCtx) error {
	if err := p.AccountContextParams.SetDefaults(ctx); err != nil {
		return err
	}
	p.SignerParams.SetDefaults(nkeys.PrefixByteAccount, true, ctx)
	p.create = true
	p.Entity.kind = nkeys.PrefixByteUser
	p.editFn = p.editUserClaim

	return nil
}

func (p *AddUserParams) PreInteractive(ctx ActionCtx) error {
	var err error
	if err = p.Entity.Edit(); err != nil {
		return err
	}

	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}

	ok, err := cli.PromptYN("Set response permissions?")
	if err != nil {
		return err
	}
	if ok {
		p.respMax, err = cli.Prompt("Number of max responses", p.respMax, true, func(v string) error {
			_, err := strconv.ParseInt(v, 10, 32)
			if err != nil {
				return err
			}
			return nil
		})
		p.respTTL, err = cli.Prompt("Response Permission TTL", p.respTTL, true, func(v string) error {
			_, err := time.ParseDuration(v)
			if err != nil {
				return err
			}
			return nil
		})
	}

	if err = p.TimeParams.Edit(); err != nil {
		return err
	}

	if err = p.SignerParams.Edit(ctx); err != nil {
		return err
	}

	return nil
}

func (p *AddUserParams) Load(ctx ActionCtx) error {
	return nil
}

func (p *AddUserParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *AddUserParams) Validate(ctx ActionCtx) error {
	var err error
	if p.name == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return fmt.Errorf("user name is required")
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

	return p.Entity.Valid()
}

func (p *AddUserParams) Run(ctx ActionCtx) error {
	if err := p.Entity.StoreKeys(p.AccountContextParams.Name); err != nil {
		return err
	}
	if err := p.Entity.GenerateClaim(p.signerKP, ctx); err != nil {
		return err
	}

	// FIXME: super hack
	ks := ctx.StoreCtx().KeyStore
	if p.kp == nil {
		ctx.CurrentCmd().Println("unable to save creds - user key not found")
	}

	d, err := GenerateConfig(ctx.StoreCtx().Store, p.AccountContextParams.Name, p.name, p.kp)
	if err != nil {
		ctx.CurrentCmd().Printf("unable to save creds: %v", err)
	} else {
		p.credsFilePath, err = ks.MaybeStoreUserCreds(p.AccountContextParams.Name, p.name, d)
		if err != nil {
			ctx.CurrentCmd().Println(err.Error())
		}
	}

	return nil
}

func (p *AddUserParams) editUserClaim(c interface{}, ctx ActionCtx) error {
	uc, ok := c.(*jwt.UserClaims)
	if !ok {
		return errors.New("unable to cast to user claim")
	}

	if p.TimeParams.IsStartChanged() {
		uc.NotBefore, _ = p.TimeParams.StartDate()
	}

	if p.TimeParams.IsExpiryChanged() {
		uc.Expires, _ = p.TimeParams.ExpiryDate()
	}

	if p.respMax != "" {
		v, err := strconv.ParseInt(p.respMax, 10, 32)
		if err != nil {
			return err
		}
		if uc.Resp == nil {
			uc.Resp = &jwt.ResponsePermission{Expires: time.Millisecond * 5000}
		}
		uc.Resp.MaxMsgs = int(v)
	}

	if p.respTTL != "" {
		v, err := time.ParseDuration(p.respTTL)
		if err != nil {
			return err
		}
		if uc.Resp == nil {
			uc.Resp = &jwt.ResponsePermission{MaxMsgs: 1}
		}
		uc.Resp.Expires = v
	}

	uc.Permissions.Pub.Allow.Add(p.allowPubs...)
	uc.Permissions.Pub.Allow.Add(p.allowPubsub...)
	sort.Strings(uc.Pub.Allow)

	uc.Permissions.Pub.Deny.Add(p.denyPubs...)
	uc.Permissions.Pub.Deny.Add(p.denyPubsub...)
	sort.Strings(uc.Permissions.Pub.Deny)

	uc.Permissions.Sub.Allow.Add(p.allowSubs...)
	uc.Permissions.Sub.Allow.Add(p.allowPubsub...)
	sort.Strings(uc.Permissions.Sub.Allow)

	uc.Permissions.Sub.Deny.Add(p.denySubs...)
	uc.Permissions.Sub.Deny.Add(p.denyPubsub...)
	sort.Strings(uc.Permissions.Sub.Deny)

	uc.Tags.Add(p.tags...)
	sort.Strings(uc.Tags)

	return nil
}
