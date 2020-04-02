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
	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createDescribeAccountCmd() *cobra.Command {
	var params DescribeAccountParams
	cmd := &cobra.Command{
		Use:          "account",
		Short:        "Describes an account",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().StringVarP(&params.outputFile, "output-file", "o", "--", "output file, '--' is stdout")
	cmd.Flags().StringVarP(&params.AccountContextParams.Name, "name", "n", "", "account name")

	return cmd
}

func init() {
	describeCmd.AddCommand(createDescribeAccountCmd())
}

type DescribeAccountParams struct {
	AccountContextParams
	jwt.AccountClaims
	outputFile string
	raw        []byte
}

func (p *DescribeAccountParams) SetDefaults(ctx ActionCtx) error {
	p.AccountContextParams.Name = NameFlagOrArgument(p.AccountContextParams.Name, ctx)
	return p.AccountContextParams.SetDefaults(ctx)
}

func (p *DescribeAccountParams) PreInteractive(ctx ActionCtx) error {
	return p.AccountContextParams.Edit(ctx)
}

func (p *DescribeAccountParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.AccountContextParams.Validate(ctx); err != nil {
		return err
	}
	if Json || Raw || JsonPath != "" {
		p.raw, err = ctx.StoreCtx().Store.ReadRawAccountClaim(p.AccountContextParams.Name)
		if err != nil {
			return err
		}
		if Json || JsonPath != "" {
			p.raw, err = bodyAsJson(p.raw)
			if err != nil {
				return err
			}
			if JsonPath != "" {
				p.raw, err = GetField(p.raw, JsonPath)
				if err != nil {
					return err
				}
			}
		}
	} else {
		ac, err := ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
		if err != nil {
			return err
		}
		p.AccountClaims = *ac
	}

	return nil
}

func (p *DescribeAccountParams) Validate(_ ActionCtx) error {
	return nil
}

func (p *DescribeAccountParams) PostInteractive(_ ActionCtx) error {
	return nil
}

func (p *DescribeAccountParams) Run(_ ActionCtx) (store.Status, error) {
	if Raw || Json || JsonPath != "" {
		if !IsStdOut(p.outputFile) {
			var err error
			p.raw, err = jwt.DecorateJWT(string(p.raw))
			if err != nil {
				return nil, err
			}
		}
		p.raw = append(p.raw, '\n')
		if err := Write(p.outputFile, p.raw); err != nil {
			return nil, err
		}
	} else {
		v := NewAccountDescriber(p.AccountClaims).Describe()
		if err := Write(p.outputFile, []byte(v)); err != nil {
			return nil, err
		}
	}
	var s store.Status
	if !IsStdOut(p.outputFile) {
		k := "description"
		if Raw {
			k = "jwt"
		}
		s = store.OKStatus("wrote account %s to %#q", k, AbbrevHomePaths(p.outputFile))
	}
	return s, nil
}
