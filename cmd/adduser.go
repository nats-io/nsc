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
	"errors"
	"fmt"
	"sort"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createAddUserCmd() *cobra.Command {
	var params AddUserParams
	cmd := &cobra.Command{
		Use:           "user",
		Short:         "Add an user to the account",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			params.create = true
			params.kind = nkeys.PrefixByteUser
			params.editFn = params.editUserClaim

			if InteractiveFlag {
				if err := params.Interactive(); err != nil {
					return err
				}
			}

			if err := params.Validate(); err != nil {
				return err
			}

			if err := params.Run(); err != nil {
				return err
			}

			if params.generated {
				cmd.Printf("Generated user key - private key stored %q\n", params.keyPath)
			} else {
				cmd.Printf("Success! - added user %q\n", params.name)
			}

			return RunInterceptor(cmd)
		},
	}

	cmd.Flags().StringVarP(&params.accountName, "account", "a", "", "account name")

	cmd.Flags().StringSliceVarP(&params.allowPubs, "allow-pub", "", nil, "publish permissions - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.allowPubsub, "allow-pubsub", "", nil, "publish and subscribe permissions - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.allowSubs, "allow-sub", "", nil, "subscribe permissions - comma separated list or option can be specified multiple times")

	cmd.Flags().StringSliceVarP(&params.denyPubs, "deny-pub", "", nil, "deny publish permissions - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.denyPubsub, "deny-pubsub", "", nil, "deny publish and subscribe permissions - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.denySubs, "deny-sub", "", nil, "deny subscribe permissions - comma separated list or option can be specified multiple times")

	cmd.Flags().StringSliceVarP(&params.tags, "tag", "", nil, "tags for user - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.src, "source-network", "", nil, "source network for connection - comma separated list or option can be specified multiple times")

	cmd.Flags().StringVarP(&params.name, "name", "", "", "name to assign the user")
	cmd.Flags().StringVarP(&params.keyPath, "public-key", "k", "", "public key identifying the user")
	cmd.Flags().StringVarP(&params.payload, "max-payload", "", "", "max message payload - number followed by units (b)yte, (k)b, (M)egabyte")
	cmd.Flags().StringVarP(&params.max, "max-messages", "", "", "max messages - number optionally followed by units (K)ilo, (M)illion, (G)iga")

	return cmd
}

func init() {
	addCmd.AddCommand(createAddUserCmd())
}

type AddUserParams struct {
	Entity
	accountKP   nkeys.KeyPair
	accountName string

	allowPubs   []string
	allowPubsub []string
	allowSubs   []string

	denyPubs   []string
	denyPubsub []string
	denySubs   []string

	max     string
	payload string
	src     []string
	tags    []string
}

func (p *AddUserParams) Interactive() error {
	if err := p.Edit(); err != nil {
		return err
	}

	s, err := GetStore()
	if err != nil {
		return err
	}

	if p.accountName == "" {
		ctx, err := s.GetContext()
		if err != nil {
			return err
		}
		p.accountName = ctx.Account.Name
	}

	if p.accountName == "" {
		accounts, err := s.ListSubContainers(store.Accounts)
		if err != nil {
			return err
		}
		if len(accounts) > 1 {
			i, err := cli.PromptChoices("user account", accounts)
			if err != nil {
				return err
			}
			p.accountName = accounts[i]
		}
	}
	return nil
}

func (p *AddUserParams) Validate() error {
	s, err := GetStore()
	if err != nil {
		return err
	}
	ctx, err := s.GetContext()
	if err != nil {
		return err
	}
	if p.accountName == "" {
		p.accountName = ctx.Account.Name
	}

	if p.accountName == "" {
		// default account was not found by get context, so we either we have none or many
		accounts, err := s.ListSubContainers(store.Accounts)
		if err != nil {
			return err
		}
		c := len(accounts)
		if c == 0 {
			return errors.New("no accounts defined - add account first")
		} else {
			return errors.New("multiple accounts found - specify --account-name or navigate to an account directory")
		}
	}

	// allow downstream validation to have a surrogate account name
	if ctx.Account.Name == "" {
		ctx.Account.Name = p.accountName
	}

	p.accountKP, err = ctx.ResolveKey(nkeys.PrefixByteAccount, KeyPathFlag)
	if err != nil {
		return fmt.Errorf("specify the account private key with --private-key to use for signing the user")
	}

	if p.max != "" {
		if _, err := ParseNumber(p.max); err != nil {
			return err
		}
	}

	if p.payload != "" {
		if _, err := ParseDataSize(p.payload); err != nil {
			return err
		}
	}

	return p.Entity.Valid()
}

func (p *AddUserParams) Run() error {
	s, err := GetStore()
	if err != nil {
		return err
	}

	if err := p.Entity.StoreKeys(s.GetName()); err != nil {
		return err
	}

	if err := p.Entity.GenerateClaim(p.accountKP); err != nil {
		return err
	}

	return nil
}

func (p *AddUserParams) editUserClaim(c interface{}) error {
	uc, ok := c.(*jwt.UserClaims)
	if !ok {
		return errors.New("unable to cast to user claim")
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

	uc.User.Limits.Max, _ = ParseNumber(p.max)
	uc.User.Limits.Payload, _ = ParseDataSize(p.payload)

	return nil
}
