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

	"github.com/nats-io/jwt"

	"github.com/nats-io/nkeys"
	"github.com/spf13/cobra"
)

func createEditAccount() *cobra.Command {
	var params EditAccountParams
	cmd := &cobra.Command{
		Use:           "account",
		Short:         "Edit an account",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if NothingToDo(cmd, "start", "expiry") {
				cmd.SilenceUsage = false
				return fmt.Errorf("specify an edit option")
			}

			if err := params.Init(); err != nil {
				return err
			}

			if InteractiveFlag {
				if err := params.Interactive(); err != nil {
					return err
				}
			}

			if err := params.Validate(cmd); err != nil {
				return err
			}

			if err := params.Run(); err != nil {
				return err
			}

			cmd.Printf("Success! - edited account %q\n", params.accountName)

			Write("--", FormatJwt("Account", params.token))

			if params.claim.NotBefore > 0 {
				cmd.Printf("Token valid on %s - %s\n",
					UnixToDate(params.claim.NotBefore),
					HumanizedDate(params.claim.NotBefore))
			}
			if params.claim.Expires > 0 {
				cmd.Printf("Token expires on %s - %s\n",
					UnixToDate(params.claim.Expires),
					HumanizedDate(params.claim.Expires))
			}

			return RunInterceptor(cmd)
		},
	}
	cmd.Flags().StringVarP(&params.accountName, "name", "n", "", "account name")
	params.BindFlags(cmd)

	return cmd
}

func NothingToDo(cmd *cobra.Command, names ...string) bool {
	for _, n := range names {
		if cmd.Flag(n).Changed {
			return false
		}
	}
	return true
}

func init() {
	editCmd.AddCommand(createEditAccount())
}

type EditAccountParams struct {
	TimeParams
	claim       *jwt.AccountClaims
	accountName string
	operatorKP  nkeys.KeyPair
	token       string
}

func (p *EditAccountParams) Init() error {
	s, err := GetStore()
	if err != nil {
		return err
	}

	if p.accountName == "" {
		ctx, err := s.GetContext()
		if err != nil {
			return err
		}
		p.accountName = ctx.Account.Name
	}
	return nil
}

func (p *EditAccountParams) Interactive() error {
	return p.TimeParams.Edit()
}

func (p *EditAccountParams) Validate(cmd *cobra.Command) error {
	if p.accountName == "" {
		cmd.SilenceUsage = false
		return fmt.Errorf("account name is required")
	}

	if err := p.TimeParams.Validate(); err != nil {
		return err
	}

	s, err := GetStore()
	if err != nil {
		return err
	}
	ctx, err := s.GetContext()
	if err != nil {
		return err
	}
	p.operatorKP, err = ctx.ResolveKey(nkeys.PrefixByteOperator, KeyPathFlag)
	if err != nil {
		return err
	}

	p.claim, err = s.ReadAccountClaim(p.accountName)
	if err != nil {
		return err
	}

	if cmd.Flag("start").Changed {
		p.claim.NotBefore, err = p.TimeParams.StartDate()
		if err != nil {
			return err
		}
	}

	if cmd.Flag("expiry").Changed {
		p.claim.Expires, err = p.TimeParams.ExpiryDate()
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *EditAccountParams) Run() error {
	s, err := GetStore()
	if err != nil {
		return err
	}
	p.token, err = p.claim.Encode(p.operatorKP)
	return s.StoreClaim([]byte(p.token))
}
