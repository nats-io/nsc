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
	"strings"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
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

	return cmd
}

func init() {
	addCmd.AddCommand(createAddUserCmd())
}

type AddUserParams struct {
	generate    bool
	name        string
	outputFile  string
	publicKey   string
	seed        []byte
	allowPubs   []string
	allowPubsub []string
	allowSubs   []string
	denyPubs    []string
	denySubs    []string
	denyPubsub  []string
	tags        []string
	max         string
	payload     string
	src         []string
}

func (p *AddUserParams) Validate() error {
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

	u := NewUser(p.publicKey)
	u.Name = p.name

	u.Pub.Allow.Add(p.allowPubs...)
	u.Pub.Deny.Add(p.denyPubs...)

	u.Sub.Allow.Add(p.allowSubs...)
	u.Sub.Deny.Add(p.denySubs...)
	u.Tag.Add(p.tags...)

	if p.max != "" {
		u.Max, _ = ParseNumber(p.max)
	}

	if p.payload != "" {
		u.Payload, _ = ParseDataSize(p.payload)
	}

	var src jwt.StringList
	for _, v := range p.src {
		src.Add(v)
	}
	sort.Strings(src)
	u.Src = strings.Join(src, ",")

	return u.Store(false)
}
