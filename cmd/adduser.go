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
		Use:   "user",
		Short: "Add an user to the account",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := params.Validate(); err != nil {
				return err
			}

			if err := params.Run(); err != nil {
				return err
			}

			if params.generate {
				d := FormatKeys("user", params.publicKey, string(params.seed))
				if err := Write(params.outputFile, d); err != nil {
					return err
				}
			} else {
				cmd.Printf("Success! - added user %q\n", params.publicKey)
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&params.generate, "generate-nkeys", "", false, "generate nkeys")
	cmd.Flags().StringVarP(&params.account, "account", "", "", "account name")

	cmd.Flags().StringSliceVarP(&params.allowPubs, "allow-pub", "", nil, "publish permissions - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.allowPubsub, "allow-pubsub", "", nil, "publish and subscribe permissions - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.allowSubs, "allow-sub", "", nil, "subscribe permissions - comma separated list or option can be specified multiple times")

	cmd.Flags().StringSliceVarP(&params.denyPubs, "deny-pub", "", nil, "deny publish permissions - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.denyPubsub, "deny-pubsub", "", nil, "deny publish and subscribe permissions - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.denySubs, "deny-sub", "", nil, "deny subscribe permissions - comma separated list or option can be specified multiple times")

	cmd.Flags().StringSliceVarP(&params.tags, "tag", "", nil, "tags for user - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.src, "source-network", "", nil, "source network for connection - comma separated list or option can be specified multiple times")

	cmd.Flags().StringVarP(&params.name, "name", "", "", "name to assign the user")
	cmd.Flags().StringVarP(&params.outputFile, "output-file", "o", "--", "output file, '--' is stdout")
	cmd.Flags().StringVarP(&params.publicKey, "public-key", "k", "", "public key identifying the user")
	cmd.Flags().StringVarP(&params.payload, "max-payload", "", "", "max message payload - number followed by units (b)yte, (k)b, (M)egabyte")
	cmd.Flags().StringVarP(&params.max, "max-messages", "", "", "max messages - number optionally followed by units (K)ilo, (M)illion, (G)iga")

	cmd.MarkFlagRequired("name")

	return cmd
}

func init() {
	addCmd.AddCommand(createAddUserCmd())
}

type AddUserParams struct {
	kp          nkeys.KeyPair
	account     string
	allowPubs   []string
	allowPubsub []string
	allowSubs   []string

	denyPubs   []string
	denyPubsub []string
	denySubs   []string

	generate   bool
	max        string
	name       string
	outputFile string
	payload    string
	publicKey  string
	seed       []byte
	src        []string
	tags       []string
}

func (p *AddUserParams) Validate() error {
	s, err := getStore()
	if err != nil {
		return err
	}
	if p.account == "" {
		a, err := s.ListSubContainers(store.Accounts)
		if err != nil {
			return err
		}
		if len(a) == 0 {
			return fmt.Errorf("no accounts defined")
		}
		if len(a) > 1 {
			return fmt.Errorf("multiple accounts defined specify --account to disambiguiate")
		}

		p.account = a[0]
	}

	ks := store.NewKeyStore()
	p.kp, err = ks.GetAccountKey(s.GetName(), p.account)
	if err != nil {
		return err
	}
	if p.kp == nil {
		return fmt.Errorf("account private key was not found - specify it with -K")
	}

	if p.publicKey != "" && p.generate {
		return fmt.Errorf("error specify one of --public-key or --generate-nkeys")
	}
	if !p.generate && p.publicKey == "" {
		return fmt.Errorf("provide --public-key or --generate-nkeys flags")
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
	var kp nkeys.KeyPair
	if p.generate {
		kp, err = nkeys.CreateUser()
		if err != nil {
			return fmt.Errorf("error generating keypair: %v", err)
		}

		pkBytes, err := kp.PublicKey()
		if err != nil {
			return fmt.Errorf("error generating public key: %v", err)
		}
		p.publicKey = string(pkBytes)

		p.seed, err = kp.Seed()
		if err != nil {
			return fmt.Errorf("error generating seed: %v", err)
		}
	}
	p.allowPubs = append(p.allowPubs, p.allowPubsub...)
	p.denyPubs = append(p.denyPubs, p.denyPubsub...)

	p.allowSubs = append(p.allowSubs, p.allowPubsub...)
	p.denySubs = append(p.denySubs, p.denyPubsub...)

	sort.Strings(p.allowPubs)
	sort.Strings(p.denyPubs)

	sort.Strings(p.allowSubs)
	sort.Strings(p.denySubs)

	sort.Strings(p.tags)

	uc := jwt.NewUserClaims(p.publicKey)
	uc.Name = p.name
	uc.User.Permissions.Sub.Allow = p.allowSubs
	uc.User.Permissions.Sub.Deny = p.denySubs
	uc.User.Permissions.Pub.Allow = p.allowPubs
	uc.User.Permissions.Pub.Deny = p.denyPubs
	uc.User.Limits.Max, _ = ParseNumber(p.max)
	uc.User.Limits.Payload, _ = ParseDataSize(p.payload)

	us, err := uc.Encode(p.kp)
	if err != nil {
		return err
	}

	s, err := getStore()
	if err != nil {
		return err
	}

	return s.Write([]byte(us), store.Accounts, p.account, store.Users, fmt.Sprintf("%s.jwt", uc.Name))
}
