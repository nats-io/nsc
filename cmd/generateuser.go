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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nsc/cmd/store"

	"github.com/nats-io/jwt"
	"github.com/spf13/cobra"
)

func createGenerateUserCmd() *cobra.Command {
	var params GenerateUserParams
	var cmd = &cobra.Command{
		Use:   "user",
		Short: "Generate an user JWT",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := params.Validate(); err != nil {
				return err
			}
			if err := params.Interact(); err != nil {
				return err
			}
			if err := params.Run(); err != nil {
				return err
			}
			if !IsStdOut(params.outputFile) {
				cmd.Printf("Success! - wrote user jwt to %q\n", params.outputFile)
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&params.prompt, "prompt", "i", false, "prompt for user")
	cmd.Flags().BoolVarP(&params.json, "json", "", false, "export user as JSON - JSON format can be re-imported")
	cmd.Flags().StringVarP(&params.expiry, "expiry", "e", "30d", "expiry for jwt (default 30 days - specify '0' for no expiration) - supported patterns include: yyyy-mm-dd, n(m)inutes, n(h)ours, n(d)ays, n(w)eeks, n(M)onths, n(y)ears")
	cmd.Flags().StringSliceVarP(&params.publicKeys, "public-key", "k", nil, "public key identifying the user")
	cmd.Flags().StringVarP(&params.outputFile, "output-file", "o", "--", "output file, '--' is stdout")
	cmd.Flags().StringVarP(&params.match, "match", "m", "", "modify all users matching the value provided - matches can happen in public key, name or tag")

	if !show {
		cmd.Flags().MarkHidden("json")
	}

	return cmd
}

type GenerateUserParams struct {
	prompt     bool
	json       bool
	expiry     string
	publicKeys []string
	outputFile string
	match      string
}

func (p *GenerateUserParams) Validate() error {
	if p.prompt && p.match != "" {
		return fmt.Errorf("error specify one of --interactive or --match to select an user")
	}
	if p.match != "" {
		return nil
	}
	if p.publicKeys == nil && !p.prompt {
		return fmt.Errorf("error specify one of --public-key or --interactive to the user to export")
	}
	if p.expiry != "" {
		expiry, err := ParseExpiry(p.expiry)
		if err != nil {
			return err
		}
		if expiry > 0 && time.Now().Unix() > expiry {
			return errors.New("expiry date is already past")
		}
	}
	return nil
}

func (p *GenerateUserParams) Interact() error {
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
		for _, u := range users {
			p.publicKeys = append(p.publicKeys, u.PublicKey)
		}
	}

	return nil
}

func (p *GenerateUserParams) ExportJWT() error {
	s, err := getStore()
	if err != nil {
		return err
	}

	if s.Has(store.AccountActivation) {
		activation, err := s.GetAccountActivation()
		if err != nil {
			return fmt.Errorf("error loading account activation: %v\n", err)
		}

		_, err = jwt.DecodeActivationClaims(activation)
		if err != nil {
			return fmt.Errorf("error decoding account activation jwt: %v\n", err)
		}
	}

	buf := bytes.NewBuffer(nil)
	for i, k := range p.publicKeys {
		if i > 0 {
			buf.WriteByte('\n')
		}
		u := User{}
		u.PublicKey = k
		if err := u.Load(); err != nil {
			return err
		}

		claims := jwt.NewUserClaims(k)
		claims.Name = u.Name
		claims.Expires, err = ParseExpiry(p.expiry)
		if err != nil {
			return err
		}
		claims.Permissions.Pub.Allow = u.Pub.Allow
		claims.Permissions.Pub.Deny = u.Pub.Deny

		claims.Permissions.Sub.Allow = u.Sub.Allow
		claims.Permissions.Sub.Deny = u.Sub.Deny

		if u.Max > 0 {
			claims.Limits.Max = u.Max
		}

		if u.Payload > 0 {
			claims.Limits.Payload = u.Payload
		}

		if u.Src != "" {
			claims.Limits.Src = u.Src
		}

		pk, err := GetSeed()
		if err != nil {
			return err
		}

		token, err := claims.Encode(pk)
		if err != nil {
			return fmt.Errorf("error generating user jwt: %v\n", err)
		}

		pk.Wipe()

		if err := s.WriteToken(token); err != nil {
			return err
		}

		label := "user"
		if len(p.publicKeys) > 1 {
			label = fmt.Sprintf("user %s", k)
		}

		d := FormatJwt(label, token)
		buf.Write(d)
	}
	if err := Write(p.outputFile, buf.Bytes()); err != nil {
		return err
	}

	return nil
}

func (p *GenerateUserParams) ExportJSON() error {
	var users []User
	for _, k := range p.publicKeys {
		u := User{}
		u.PublicKey = k
		if err := u.Load(); err != nil {
			return err
		}
		users = append(users, u)
	}

	d, err := json.MarshalIndent(&users, "", " ")
	if err != nil {
		return err
	}

	return Write(p.outputFile, d)
}

func (p *GenerateUserParams) Run() error {
	if p.json {
		return p.ExportJSON()
	}
	return p.ExportJWT()
}

func init() {
	generateCmd.AddCommand(createGenerateUserCmd())

}
