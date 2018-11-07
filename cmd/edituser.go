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
	"github.com/spf13/cobra"
)

func createEditUserCmd() *cobra.Command {
	var params EditUserParams
	var cmd = &cobra.Command{
		Use:   "user",
		Short: "Edit user values",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := params.Validate(); err != nil {
				return err
			}
			if err := params.Interact(); err != nil {
				return err
			}

			if err := params.Run(cmd); err != nil {
				return err
			}
			cmd.Printf("Success! - %d user(s) edited\n", len(params.publicKeys))
			return nil
		},
	}

	cmd.Flags().BoolVarP(&params.prompt, "interactive", "i", false, "prompt for user")
	cmd.Flags().StringSliceVarP(&params.allowPubs, "allow-pub", "", nil, "add publish permission - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.allowPubsub, "allow-pubsub", "", nil, "add publish and subscribe permission - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.allowSubs, "allow-sub", "", nil, "add subscribe permission - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.denyPubs, "deny-pub", "", nil, "add deny publish permission - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.denySubs, "deny-sub", "", nil, "add deny subscribe permission - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.denyPubsub, "deny-pubsub", "", nil, "add deny publish subscribe permission - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.addTags, "add-tag", "", nil, "add tag - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.remove, "rm", "", nil, "remove publish/subscribe and deny permissions - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.rmTags, "rm-tag", "", nil, "remove tag - comma separated list or option can be specified multiple times")
	cmd.Flags().StringVarP(&params.name, "name", "", "", "user name")
	cmd.Flags().StringSliceVarP(&params.publicKeys, "public-key", "k", nil, "public key identifying the user - comma separated list or option can be specified multiple times")
	cmd.Flags().StringVarP(&params.match, "match", "m", "", "modify all users matching the value provided - matches can happen in public key, name or tag")
	cmd.Flags().StringVarP(&params.payload, "max-payload", "", "", "max message payload - number followed by units (b)yte, (k)b, (M)egabyte")
	cmd.Flags().StringVarP(&params.max, "max-messages", "", "", "max messages - number optionally followed by units (K)ilo, (M)illion, (G)iga")
	cmd.Flags().StringSliceVarP(&params.addSrc, "add-source-network", "", nil, "add source network for connection - comma separated list or option can be specified multiple times")
	cmd.Flags().StringSliceVarP(&params.rmSrc, "rm-source-network", "", nil, "remove source network for connection - comma separated list or option can be specified multiple times")

	return cmd
}

func init() {
	editCmd.AddCommand(createEditUserCmd())
}

type EditUserParams struct {
	allowPubs   []string
	allowSubs   []string
	allowPubsub []string
	denyPubs    []string
	denySubs    []string
	denyPubsub  []string
	remove      []string
	name        string
	prompt      bool
	publicKeys  []string
	addTags     []string
	rmTags      []string
	match       string
	max         string
	payload     string
	addSrc      []string
	rmSrc       []string
}

func (p *EditUserParams) Validate() error {
	if p.prompt && p.match != "" {
		return fmt.Errorf("error specify one of --interactive or --match to select an user")
	}
	if p.match != "" {
		return nil
	}
	if p.publicKeys == nil && !p.prompt {
		return fmt.Errorf("error specify one of --public-key or --interactive to select an user")
	}
	if p.max != "" {
		if _, err := ParseNumber(p.max); err != nil {
			return fmt.Errorf("error parsing max-messages %q: %v", p.max, err)
		}
	}
	if p.payload != "" {
		if _, err := ParseDataSize(p.payload); err != nil {
			return fmt.Errorf("error parsing max-payload %q: %v", p.payload, err)
		}
	}
	return nil
}

func (p *EditUserParams) Interact() error {
	if !p.prompt && p.match == "" {
		return nil
	}

	if p.match != "" {
		users, err := ListUsers()
		if err != nil {
			return err
		}
		for _, v := range users {
			if v.Matches(p.match) {
				p.publicKeys = append(p.publicKeys, v.PublicKey)
			}
		}

		if len(p.publicKeys) == 0 {
			return fmt.Errorf("error %q didn't match anything", p.match)
		}
	}

	if p.publicKeys == nil {
		users, err := PickUsers()
		if err != nil {
			return err
		}
		for _, v := range users {
			p.publicKeys = append(p.publicKeys, v.PublicKey)
		}
	}

	return nil
}

func (p *EditUserParams) Run(cmd *cobra.Command) error {
	for _, v := range p.publicKeys {
		u := User{}
		u.PublicKey = v
		if err := u.Load(); err != nil {
			return err
		}
		// only change if the flag was provided
		if cmd.Flag("name").Changed {
			u.Name = p.name
		}

		if p.max != "" {
			u.Max, _ = ParseNumber(p.max)
		}

		if p.payload != "" {
			u.Payload, _ = ParseDataSize(p.payload)
		}

		u.Pub.Allow.Add(p.allowPubs...)
		u.Pub.Allow.Add(p.allowPubsub...)
		u.Pub.Allow.Remove(p.remove...)

		u.Pub.Deny.Add(p.denyPubs...)
		u.Pub.Deny.Add(p.denyPubsub...)
		u.Pub.Deny.Remove(p.remove...)

		u.Sub.Allow.Add(p.allowSubs...)
		u.Sub.Allow.Add(p.allowPubsub...)
		u.Sub.Allow.Remove(p.remove...)

		u.Sub.Deny.Add(p.denySubs...)
		u.Sub.Deny.Add(p.denyPubsub...)
		u.Sub.Deny.Remove(p.remove...)

		u.Tag.Add(p.addTags...)
		u.Tag.Remove(p.rmTags...)

		sort.Strings(u.Pub.Allow)
		sort.Strings(u.Pub.Deny)
		sort.Strings(u.Sub.Allow)
		sort.Strings(u.Sub.Deny)
		sort.Strings(u.Tag)

		var src jwt.StringList
		src.Add(strings.Split(u.Src, ",")...)
		src.Add(p.addSrc...)
		src.Remove(p.rmSrc...)
		sort.Strings(src)
		u.Src = strings.Join(src, ",")

		if err := u.Store(true); err != nil {
			return err
		}
	}
	return nil
}
