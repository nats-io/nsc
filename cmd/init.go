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
	"strings"

	"github.com/nats-io/nkeys"
	"github.com/spf13/cobra"
)

func createInitCmd() *cobra.Command {
	var params InitParams

	var cmd = &cobra.Command{
		Use:    "init",
		Hidden: !show,
		Short:  "initializes an directory for an account or operator",
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := params.Validate(args); err != nil {
				return err
			}
			if err := params.Run(args); err != nil {

			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&params.generate, "generate-nkeys", "", "", "generate nkeys ['account', 'operator', 'cluster']")
	cmd.Flags().StringVarP(&params.name, "name", "", "", "name to assign the profile")
	cmd.Flags().StringVarP(&params.publicKey, "public-key", "k", "", "public key identifying the user - can be a filepath or a public nkey")
	cmd.MarkFlagRequired("name")

	return cmd
}

func init() {
	rootCmd.AddCommand(createInitCmd())
}

type InitParams struct {
	generate  string
	name      string
	publicKey string
	seed      []byte
}

func (p *InitParams) Validate(args []string) error {
	var err error
	p.generate = strings.ToLower(p.generate)

	if p.generate != "" && p.publicKey != "" {
		return errors.New("specify either --generate-nkeys or --public-key")
	}

	if p.generate != "" && p.generate != "account" && p.generate != "operator" {
		return fmt.Errorf("illegal value to --generate-nkeys option %q, only 'account', 'operator'", p.generate)
	}

	if p.publicKey != "" {
		p.publicKey, err = GetKey(p.publicKey)
		if err != nil {
			return err
		}
	}

	if !OkToWrite(args[0]) {
		return fmt.Errorf("the path %q exists already", args[0])
	}

	return nil
}

func (p *InitParams) Run(args []string) error {

	var err error
	var kp nkeys.KeyPair
	if p.generate != "" {
		switch p.generate {
		case "account":
			kp, err = nkeys.CreateAccount()
		case "operator":
			kp, err = nkeys.CreateOperator()
		}

		if err != nil {
			return err
		}

		p.seed, err = kp.Seed()
		if err != nil {
			return err
		}

		d, err := kp.PublicKey()
		if err != nil {
			return err
		}
		p.publicKey = string(d)
	}
	return nil
}
