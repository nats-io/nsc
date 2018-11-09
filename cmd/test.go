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
	"os"
	"time"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createTestCmd() *cobra.Command {
	var testCmd = &cobra.Command{
		Use:    "test",
		Short:  "cli test util",
		Hidden: !show,
	}

	var initCmd = &cobra.Command{
		Use:    "init",
		Hidden: !show,
		Short:  "initializes a test store",
		RunE: func(cmd *cobra.Command, args []string) error {
			kp, err := nkeys.CreateAccount()
			if err != nil {
				return err
			}

			pk, err := kp.PublicKey()
			if err != nil {
				return err
			}

			dir, err := store.FindCurrentStoreDir()
			if err != nil {
				return err
			}

			s, err := store.CreateStore(dir, string(pk))
			if err != nil {
				return err
			}

			okp, err := nkeys.CreateOperator()
			if err != nil {
				return err
			}

			pub, err := kp.PublicKey()
			if err != nil {
				return err
			}

			ac := jwt.NewActivationClaims(string(pub))
			ac.Expires = time.Now().AddDate(0, 1, 0).Unix()
			ac.Name = "Operator Activation"
			token, err := ac.Encode(okp)
			if err != nil {
				return err
			}
			s.SetAccountActivation(token)
			cmd.Printf("initialized test store %q for profile %q\n", s.Dir, s.Profile)
			return nil
		},
	}

	var resetCmd = &cobra.Command{
		Use:    "reset",
		Short:  "Deletes the current store directory",
		Long:   `Deletes the current store directory`,
		Hidden: !show,
		Run: func(cmd *cobra.Command, args []string) {

			// TODO(sasbury) this doesn't work, you can't delete your current folder usually
			dir, err := store.FindCurrentStoreDir()
			if err != nil {
				return
			}

			ok, err := cli.PromptYN(fmt.Sprintf("delete %q", dir))
			if err != nil {
				return
			}
			if ok {
				if err := os.RemoveAll(dir); err != nil {
					fmt.Printf("error removing %q: %v", dir, err)
					return
				}
			}
			fmt.Printf("Success! - %q was deleted\n", dir)
		},
	}

	rootCmd.AddCommand(testCmd)
	testCmd.AddCommand(initCmd)
	testCmd.AddCommand(resetCmd)
	return testCmd
}

func init() {
	createTestCmd()
}
