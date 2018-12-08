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

func createDescribeAccountCmd() *cobra.Command {
	var params DescribeAccountParams
	cmd := &cobra.Command{
		Use:          "account",
		Short:        "Describes an account",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}
			if !IsStdOut(params.outputFile) {
				cmd.Printf("Success! - wrote account description to %q\n", params.outputFile)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.outputFile, "output-file", "o", "--", "output file, '--' is stdout")
	params.AccountContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	describeCmd.AddCommand(createDescribeAccountCmd())
}

type DescribeAccountParams struct {
	AccountContextParams
	jwt.AccountClaims
	outputFile string
	token      string
}

func (p *DescribeAccountParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.SetDefaults(ctx)
	return nil
}

func (p *DescribeAccountParams) PreInteractive(ctx ActionCtx) error {
	return p.AccountContextParams.Edit(ctx)
}

func (p *DescribeAccountParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}

	if !ctx.StoreCtx().Store.Has(store.Accounts, p.AccountContextParams.Name, store.JwtName(p.AccountContextParams.Name)) {
		return fmt.Errorf("account %q is not defined in the current context", p.AccountContextParams.Name)
	}
	ac, err := ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		return err
	}
	if ac != nil {
		p.AccountClaims = *ac
	}
	return nil
}

func (p *DescribeAccountParams) Validate(ctx ActionCtx) error {
	return nil
}

func (p *DescribeAccountParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *DescribeAccountParams) Run(ctx ActionCtx) error {
	v := NewAccountDescriber(p.AccountClaims).Describe()
	return Write(p.outputFile, []byte(v))
}
