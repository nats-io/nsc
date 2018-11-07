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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/nats-io/nkeys"
	"github.com/spf13/cobra"
)

func createLoadUserCmd() *cobra.Command {
	var params LoadUserParams
	var cmd = &cobra.Command{
		Use:    "user",
		Short:  "Load user",
		Hidden: !show,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := params.Validate(); err != nil {
				return err
			}
			users, err := params.LoadUsers()
			if err != nil {
				return err
			}

			for _, u := range users {
				if err := u.Store(params.overwrite); err != nil {
					return err
				}
			}

			cmd.Printf("Success! - loaded %d users\n", len(users))

			return nil
		},
	}
	cmd.Flags().StringVarP(&params.filepath, "in-file", "f", "", "file to input users from")
	cmd.Flags().BoolVarP(&params.overwrite, "overwrite", "", false, "overwrite users having the same public key")
	cmd.MarkFlagRequired("in")
	return cmd
}

func init() {
	loadCmd.AddCommand(createLoadUserCmd())

}

type LoadUserParams struct {
	overwrite bool
	filepath  string
}

func (p *LoadUserParams) Validate() error {
	if !IsReadableFile(p.filepath) {
		return fmt.Errorf("file %q doesn't exist or is not readable", p.filepath)
	}
	return nil
}

func (p *LoadUserParams) LoadUsers() ([]User, error) {
	d, err := ioutil.ReadFile(p.filepath)
	if err != nil {
		return nil, fmt.Errorf("error reading %q: %v", p.filepath, err)
	}

	var users []User

	if d[0] == '[' {
		if err := json.Unmarshal(d, &users); err != nil {
			return nil, fmt.Errorf("error parsing users in %q: %v", p.filepath, err)
		}

		if len(users) == 0 {
			return nil, fmt.Errorf("no users defined in %q", p.filepath)
		}
	} else {
		u := User{}
		if err := json.Unmarshal(d, &u); err != nil {
			return nil, fmt.Errorf("error parsing uses in %q: %v", p.filepath, err)
		}
		users = append(users, u)
	}

	for i, u := range users {
		uu := User{}
		uu.Name = u.Name
		u.PublicKey = strings.TrimSpace(u.PublicKey)
		if u.PublicKey == "" {
			return nil, fmt.Errorf("user [%d] is missing a public key", i)
		}

		if LooksLikeNKey(u.PublicKey, 'U') {
			kp, err := ParseNKey(u.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("error parsing public key [%d]: %v", i, err)
			}
			pkbytes, err := kp.PublicKey()
			if err != nil {
				return nil, fmt.Errorf("error reading public key [%d]: %v", i, err)
			}
			u.PublicKey = string(pkbytes)
		}

		if !nkeys.IsValidPublicUserKey([]byte(u.PublicKey)) {
			return nil, fmt.Errorf("user's [%d] public key %q is not a valid user public key", i, u.PublicKey)
		}
		uu.PublicKey = u.PublicKey

		uu.Pub.Allow.Add(u.Pub.Allow...)
		uu.Pub.Deny.Add(u.Pub.Deny...)

		uu.Sub.Allow.Add(u.Sub.Allow...)
		uu.Sub.Deny.Add(u.Sub.Deny...)

		uu.Tag = u.Tag

		users[i] = uu
	}

	return users, nil
}
