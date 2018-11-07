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
	"os"

	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
	"github.com/spf13/cobra"
)

func createStatusCmd() *cobra.Command {
	var params StatusParams
	var cmd = &cobra.Command{
		Use:   "status",
		Short: "Reports the status of the account",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := params.Validate(); err != nil {
				return err
			}

			if err := params.Run(); err != nil {
				return err
			}

			if params.firstTime {
				if err := params.createDefaultUser(); err != nil {
					return err
				}
			}

			cmd.Println()
			cmd.Println(cli.Wrap(80, "Type 'ncs help' for commands to create and generate configuration assets."))

			return nil
		},
	}
	return cmd
}

func init() {
	rootCmd.AddCommand(createStatusCmd())
}

type StatusParams struct {
	firstTime bool
	outdir    string
}

func (p *StatusParams) Validate() error {
	s, err := getStore()
	if err != nil {
		return err
	}
	_, err = s.GetAccountActivation()
	p.firstTime = os.IsNotExist(err)

	_, err = s.GetPublicKey()
	if os.IsNotExist(err) {
		return fmt.Errorf("account public key doesn't exist: %v", err)
	}
	return nil
}

func (p *StatusParams) Run() error {
	err := p.getAccountStatus()
	if err != nil {
		return err
	}
	return nil
}

func (p *StatusParams) getAccountStatus() error {
	s, err := getStore()
	if err != nil {
		return err
	}

	_, err = s.GetPublicKey()
	if err != nil {
		return err
	}

	return nil
}

func (p *StatusParams) createDefaultUser() error {
	ok, err := cli.PromptYN("Do you want to create a default user")
	if err != nil {
		return err
	}
	if ok {
		p.outdir, err = cli.Prompt("Directory to create an user environment", "", false, func(dir string) error {
			if dir == "--" {
				return errors.New("must be a directory")
			}
			if !OkToWrite(dir) {
				return errors.New(fmt.Sprintf("directory/file %q exists", dir))
			}
			return nil
		})
		if err != nil {
			return err
		}

		kp, err := nkeys.CreateUser()
		if err != nil {
			return err
		}

		pk, err := kp.PublicKey()
		if err != nil {
			return err
		}

		sk, err := kp.Seed()
		if err != nil {
			return err
		}

		rootCmd.SetArgs([]string{"add", "user", "--public-key", string(pk), "--name", "default"})
		if err := rootCmd.Execute(); err != nil {
			return err
		}

		rootCmd.SetArgs([]string{"generate", "environment", "--outdir", p.outdir, "--public-key", string(pk), "--private-key", string(sk)})
		if err := rootCmd.Execute(); err != nil {
			return err
		}
	}
	return nil
}

func (p *StatusParams) render() (string, error) {
	return "not implemented", nil
}
