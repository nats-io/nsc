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

// addCmd represents the add command
var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Test commands",
}

type GenerateNKeysParam struct {
	operator bool
	account  bool
	user     bool
	cluster  bool
	server   bool
}

func (p *GenerateNKeysParam) PrintKey(kind nkeys.PrefixByte, cmd *cobra.Command) {
	kp, err := store.CreateNKey(kind)
	if err != nil {
		panic(err)
	}
	pub, err := kp.PublicKey()
	cmd.Println(string(pub))
}

func (p *GenerateNKeysParam) Run(cmd *cobra.Command) error {
	if p.operator {
		p.PrintKey(nkeys.PrefixByteOperator, cmd)
	}
	if p.account {
		p.PrintKey(nkeys.PrefixByteAccount, cmd)
	}
	if p.user {
		p.PrintKey(nkeys.PrefixByteUser, cmd)
	}
	if p.cluster {
		p.PrintKey(nkeys.PrefixByteCluster, cmd)
	}
	if p.server {
		p.PrintKey(nkeys.PrefixByteServer, cmd)
	}
	return RunInterceptor(nil)
}

func createGenerateNkey() *cobra.Command {
	var params GenerateNKeysParam
	cmd := &cobra.Command{
		Use:           "nkey",
		Short:         "Generates an nkey",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return params.Run(cmd)
		},
	}
	cmd.Flags().BoolVarP(&params.operator, "operator", "o", false, "operator")
	cmd.Flags().BoolVarP(&params.account, "account", "a", false, "account")
	cmd.Flags().BoolVarP(&params.user, "user", "u", false, "user")
	cmd.Flags().BoolVarP(&params.cluster, "cluster", "c", false, "cluster")
	cmd.Flags().BoolVarP(&params.server, "server", "s", false, "server")

	return cmd
}

func init() {
	rootCmd.AddCommand(testCmd)
	testCmd.AddCommand(createGenerateNkey())
}
