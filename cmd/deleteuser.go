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

	"github.com/nats-io/nsc/cli"
	"github.com/spf13/cobra"
)

func createDeleteUserCmd() *cobra.Command {
	var params DeleteUserParams
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Delete one or more users",
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
			cmd.Printf("%d user(s) deleted\n", len(params.publicKeys))
			return nil
		},
	}

	cmd.Flags().BoolVarP(&params.prompt, "interactive", "i", false, "prompt for user")
	cmd.Flags().StringSliceVarP(&params.publicKeys, "public-key", "k", nil, "public key identifying the user - multiple users can be specified by providing comma separated values or the option multiple times")
	return cmd
}

func init() {
	deleteCmd.AddCommand(createDeleteUserCmd())
}

type DeleteUserParams struct {
	publicKeys []string
	prompt     bool
}

func (p *DeleteUserParams) Validate() error {
	if p.publicKeys == nil && !p.prompt {
		return fmt.Errorf("error specify one of --public-key or --interactive to the user to delete")
	}
	return nil
}

func (p *DeleteUserParams) Interact() error {
	if !p.prompt {
		return nil
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

	ok, err := cli.PromptYN(fmt.Sprintf("Delete %d user(s)", len(p.publicKeys)))
	if err != nil {
		return fmt.Errorf("error processing confirmation: %v", err)
	}

	if !ok {
		return errors.New("operation canceled")
	}

	return nil
}

func (p *DeleteUserParams) Run() error {
	for _, k := range p.publicKeys {
		u := User{}
		u.PublicKey = k
		if err := u.Delete(); err != nil {
			return err
		}
	}
	return nil
}
