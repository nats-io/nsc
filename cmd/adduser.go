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
			if err := params.Validate(); err != nil {
				return err
			}
			if err := params.Run(); err != nil {
				return err
			}
			if params.generate {
				cmd.Printf("Generated user key - private key stored %q\n", params.userKeyPath)
			} else {
				cmd.Printf("Success! - added user %q\n", params.Name)
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&params.generate, "generate-nkeys", "G", false, "generate nkeys")
	cmd.Flags().StringVarP(&params.accountName, "account-name", "", "", "account name")

	cmd.Flags().StringSliceVarP(&params.allowPubs, "allow-pub", "", nil, "publish permissions - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.allowPubsub, "allow-pubsub", "", nil, "publish and subscribe permissions - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.allowSubs, "allow-sub", "", nil, "subscribe permissions - comma separated list or option can be specified multiple times")

	cmd.Flags().StringSliceVarP(&params.denyPubs, "deny-pub", "", nil, "deny publish permissions - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.denyPubsub, "deny-pubsub", "", nil, "deny publish and subscribe permissions - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.denySubs, "deny-sub", "", nil, "deny subscribe permissions - comma separated list or option can be specified multiple times")

	cmd.Flags().StringSliceVarP(&params.tags, "tag", "", nil, "tags for user - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.src, "source-network", "", nil, "source network for connection - comma separated list or option can be specified multiple times")

	cmd.Flags().StringVarP(&params.Name, "name", "", "", "name to assign the user")
	cmd.Flags().StringVarP(&params.outputFile, "output-file", "o", "--", "output file - '--' is stdout")
	cmd.Flags().StringVarP(&params.userKeyPath, "public-key", "k", "", "public key identifying the user")
	cmd.Flags().StringVarP(&params.payload, "max-payload", "", "", "max message payload - number followed by units (b)yte, (k)b, (M)egabyte")
	cmd.Flags().StringVarP(&params.max, "max-messages", "", "", "max messages - number optionally followed by units (K)ilo, (M)illion, (G)iga")

	cmd.MarkFlagRequired("name")

	return cmd
}

func init() {
	addCmd.AddCommand(createAddUserCmd())
}

type AddUserParams struct {
	jwt.UserClaims

	accountKP   nkeys.KeyPair
	userKP      nkeys.KeyPair
	userKeyPath string

	accountName string
	allowPubs   []string
	allowPubsub []string
	allowSubs   []string

	denyPubs   []string
	denyPubsub []string
	denySubs   []string

	generate   bool
	max        string
	outputFile string
	payload    string
	src        []string
	tags       []string
}

func (p *AddUserParams) Validate() error {
	if !p.generate && p.userKeyPath == "" {
		return fmt.Errorf("provide --public-key or --generate-nkeys flags")
	}

	s, err := getStore()
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
		cNames, err := s.ListSubContainers(store.Accounts)
		if err != nil {
			return err
		}
		c := len(cNames)
		if c == 0 {
			return errors.New("no accounts defined - add account first")
		} else {
			return errors.New("multiple accounts found - specify --account-name or navigate to an account directory")
		}
	}

	if s.Has(store.Accounts, p.accountName, store.Users, store.JwtName(p.Name)) {
		return fmt.Errorf("account %q already has a user named %q", p.Name, p.Name)
	}

	p.accountKP, err = ctx.ResolveKey(nkeys.PrefixByteAccount, store.KeyPathFlag)
	if err != nil {
		return fmt.Errorf("specify the account private key with --private-key to use for signing the user")
	}

	if p.generate {
		p.userKP, err = nkeys.CreateUser()
		if err != nil {
			return fmt.Errorf("error generating an user key: %v", err)
		}
	} else {
		p.userKP, err = ctx.ResolveKey(nkeys.PrefixByteUser, p.userKeyPath)
		if err != nil {
			return fmt.Errorf("error resolving user key: %v", err)
		}
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

	return nil
}

func (p *AddUserParams) Run() error {
	var err error

	upk, err := p.userKP.PublicKey()
	if err != nil {
		return err
	}
	p.Subject = string(upk)
	p.Permissions.Pub.Allow.Add(p.allowPubs...)
	p.Permissions.Pub.Allow.Add(p.allowPubsub...)
	sort.Strings(p.UserClaims.Pub.Allow)

	p.Permissions.Pub.Deny.Add(p.denyPubs...)
	p.Permissions.Pub.Deny.Add(p.denyPubsub...)
	sort.Strings(p.Permissions.Pub.Deny)

	p.Permissions.Sub.Allow.Add(p.allowSubs...)
	p.Permissions.Sub.Allow.Add(p.allowPubsub...)
	sort.Strings(p.Permissions.Sub.Allow)

	p.Permissions.Sub.Deny.Add(p.denySubs...)
	p.Permissions.Sub.Deny.Add(p.denyPubsub...)
	sort.Strings(p.Permissions.Sub.Deny)

	p.Tags.Add(p.tags...)
	sort.Strings(p.Tags)

	p.User.Limits.Max, _ = ParseNumber(p.max)
	p.User.Limits.Payload, _ = ParseDataSize(p.payload)

	us, err := p.Encode(p.accountKP)
	if err != nil {
		return err
	}

	s, err := getStore()
	if err != nil {
		return err
	}
	if err = s.StoreClaim([]byte(us)); err != nil {
		return err
	}

	if p.generate {
		ks := store.NewKeyStore()
		if p.userKeyPath == "" {
			p.userKeyPath, err = ks.Store(s.Info.Name, p.Name, p.userKP)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
