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
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createAddAccountCmd() *cobra.Command {
	var params AddAccountParams
	cmd := &cobra.Command{
		Use:           "account",
		Short:         "Add an account",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			params.create = true
			params.kind = nkeys.PrefixByteAccount

			if params.name == "" {
				if err := params.Edit(); err != nil {
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
				cmd.Printf("Generated account key - private key stored %q\n", params.keyPath)
			} else {
				cmd.Printf("Success! - added account %q\n", params.name)
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&params.name, "name", "", "", "account name")
	cmd.Flags().StringVarP(&params.keyPath, "public-key", "k", "", "public key identifying the account")

	return cmd
}

func init() {
	addCmd.AddCommand(createAddAccountCmd())
}

type AddAccountParams struct {
	Entity
	operatorKP nkeys.KeyPair
}

func (p *AddAccountParams) Validate() error {
	s, err := getStore()
	if err != nil {
		return err
	}
	ctx, err := s.GetContext()
	if err != nil {
		return err
	}
	p.operatorKP, err = ctx.ResolveKey(nkeys.PrefixByteOperator, store.KeyPathFlag)
	if err != nil {
		return err
	}
	return p.Valid()
}

func (p *AddAccountParams) Run() error {
	s, err := getStore()
	if err != nil {
		return err
	}

	if err := p.Entity.StoreKeys(s.GetName()); err != nil {
		return err
	}

	if err := p.Entity.GenerateClaim(p.operatorKP); err != nil {
		return err
	}

	return nil
}
