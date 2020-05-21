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

	"github.com/nats-io/nsc/cmd/store"

	"github.com/nats-io/jwt"
	"github.com/spf13/cobra"
)

func createDescribeUserCmd() *cobra.Command {
	var params DescribeUserParams
	cmd := &cobra.Command{
		Use:          "user",
		Short:        "Describes an user",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
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
	raw        []byte
}

func (p *DescribeUserParams) SetDefaults(ctx ActionCtx) error {
	p.user = NameFlagOrArgument(p.user, ctx)
	return p.AccountContextParams.SetDefaults(ctx)
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

	if Json || Raw || JsonPath != "" {
		p.raw, err = ctx.StoreCtx().Store.ReadRawUserClaim(p.AccountContextParams.Name, p.user)
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
		uc, err := ctx.StoreCtx().Store.ReadUserClaim(p.AccountContextParams.Name, p.user)
		if err != nil {
			return err
		}
		p.UserClaims = *uc
	}
	return nil
}

func (p *DescribeUserParams) Validate(_ ActionCtx) error {
	return nil
}

func (p *DescribeUserParams) PostInteractive(_ ActionCtx) error {
	return nil
}

func (p *DescribeUserParams) Run(_ ActionCtx) (store.Status, error) {
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
		v := NewUserDescriber(p.UserClaims).Describe()
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
		s = store.OKStatus("wrote user %s to %#q", k, AbbrevHomePaths(p.outputFile))
	}
	return s, nil
}
