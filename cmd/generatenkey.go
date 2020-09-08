/*
 * Copyright 2018-2020 The NATS Authors
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

	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createGenerateNKeyCmd() *cobra.Command {
	var params GenerateNKeysParam
	params.operator.prefix = nkeys.PrefixByteOperator
	params.account.prefix = nkeys.PrefixByteAccount
	params.user.prefix = nkeys.PrefixByteUser

	cmd := &cobra.Command{
		Use:   "nkey",
		Short: "Generates an nkey",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunMaybeStorelessAction(cmd, args, &params)
		},
	}
	cmd.Flags().BoolVarP(&params.operator.generate, "operator", "o", false, "operator")
	cmd.Flags().BoolVarP(&params.account.generate, "account", "a", false, "account")
	cmd.Flags().BoolVarP(&params.user.generate, "user", "u", false, "user")
	cmd.Flags().BoolVarP(&params.store, "store", "S", false, "store in the keystore")

	return cmd
}

func init() {
	generateCmd.AddCommand(createGenerateNKeyCmd())
}

type GenerateNKeysParam struct {
	operator KP
	account  KP
	user     KP
	store    bool
}

type KP struct {
	generate bool
	prefix   nkeys.PrefixByte
	kp       nkeys.KeyPair
	fp       string
}

func (e *KP) kind() string {
	switch e.prefix {
	case nkeys.PrefixByteOperator:
		return "operator"
	case nkeys.PrefixByteAccount:
		return "account"
	case nkeys.PrefixByteUser:
		return "user"
	}
	return ""
}

func (e *KP) Generate() error {
	var err error
	e.kp, err = nkeys.CreatePair(e.prefix)
	if err != nil {
		panic(err)
	}
	return err
}

func (e *KP) String(pubOnly bool) string {
	if e.kp != nil {
		if pubOnly {
			pk, err := e.kp.PublicKey()
			if err != nil {
				return ""
			}
			return fmt.Sprintf("%s\n%s key stored %s\n", pk, e.kind(), e.fp)
		} else {
			seed, err := e.kp.Seed()
			if err != nil {
				return ""
			}
			pk, err := e.kp.PublicKey()
			if err != nil {
				return ""
			}
			if e.fp == "" {
				return fmt.Sprintf("%s\n%s\n", string(seed), pk)
			}
			return fmt.Sprintf("%s\n%s\n%s key stored %s\n", string(seed), pk, e.kind(), e.fp)
		}
	}
	return ""
}

func (p *GenerateNKeysParam) SetDefaults(ctx ActionCtx) error {
	if !ctx.AnySet("operator", "account", "user") {
		return fmt.Errorf("set --operator, --account, or --user")
	}
	return nil
}

func (p *GenerateNKeysParam) PreInteractive(ctx ActionCtx) error {
	return nil
}

func (p *GenerateNKeysParam) Load(ctx ActionCtx) error {
	return nil
}

func (p *GenerateNKeysParam) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *GenerateNKeysParam) Validate(ctx ActionCtx) error {
	return nil
}

func (p *GenerateNKeysParam) Run(ctx ActionCtx) (store.Status, error) {
	var err error
	var jobs []*KP
	jobs = append(jobs, &p.operator, &p.account, &p.user)
	for _, j := range jobs {
		if j.generate {
			if err := j.Generate(); err != nil {
				return nil, err
			}
			if p.store {
				j.fp, err = ctx.StoreCtx().KeyStore.Store(j.kp)
				if err != nil {
					return nil, err
				}
			}
			ctx.CurrentCmd().Println(j.String(p.store))
		}
	}
	return nil, nil
}
