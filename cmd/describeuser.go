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
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createDescribeUserCmd() *cobra.Command {
	var params DescribeUserParams
	cmd := &cobra.Command{
		Use:          "user",
		Short:        "Describes an user",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}
			if !IsStdOut(params.outputFile) {
				cmd.Printf("Success! - wrote user description to %q\n", params.outputFile)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.outputFile, "output-file", "o", "--", "output file, '--' is stdout")
	cmd.Flags().StringVarP(&params.user, "name", "n", "", "user name")
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	describeCmd.AddCommand(createDescribeUserCmd())
}

type DescribeUserParams struct {
	AccountContextParams
	jwt.UserClaims
	user       string
	outputFile string
}

func (p *DescribeUserParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.SetDefaults(ctx)
	return nil
}

func (p *DescribeUserParams) PreInteractive(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Edit(ctx); err != nil {
		return err
	}
	if p.user == "" {
		p.user, err = ctx.StoreCtx().PickUser(p.AccountContextParams.Name)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *DescribeUserParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	if p.user == "" {
		n := ctx.StoreCtx().DefaultUser(p.AccountContextParams.Name)
		if n != nil {
			p.user = *n
		}
	}

	if p.user == "" {
		return fmt.Errorf("user is required")
	}

	if !ctx.StoreCtx().Store.Has(store.Accounts, p.AccountContextParams.Name, store.Users, store.JwtName(p.user)) {
		return fmt.Errorf("user %q not found", p.user)
	}

	uc, err := ctx.StoreCtx().Store.ReadUserClaim(p.AccountContextParams.Name, p.user)
	if err != nil {
		return err
	}
	if uc != nil {
		p.UserClaims = *uc
	}
	return nil
}

func (p *DescribeUserParams) Validate(ctx ActionCtx) error {
	return nil
}

func (p *DescribeUserParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *DescribeUserParams) Run(ctx ActionCtx) error {
	v := NewUserDescriber(p.UserClaims).Describe()
	return Write(p.outputFile, []byte(v))
}
