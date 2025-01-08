/*
 * Copyright 2018-2025 The NATS Authors
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

	"github.com/nats-io/nsc/v2/cmd/store"

	"github.com/nats-io/jwt/v2"
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
	BaseDescribe
	user string
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
		p.user, err = PickUser(ctx.StoreCtx(), p.AccountContextParams.Name)
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

	p.raw, err = ctx.StoreCtx().Store.ReadRawUserClaim(p.AccountContextParams.Name, p.user)
	if err != nil {
		return err
	}
	return p.Init()
}

func (p *DescribeUserParams) PostInteractive(_ ActionCtx) error {
	return nil
}

func (p *DescribeUserParams) Validate(ctx ActionCtx) error {
	return p.AccountContextParams.Validate(ctx)
}

func (p *DescribeUserParams) Run(ctx ActionCtx) (store.Status, error) {
	if Raw || Json || JsonPath != "" {
		return p.Describe(ctx)
	}

	d, err := p.Raw(false)
	if err != nil {
		return nil, err
	}
	uc, err := jwt.DecodeUserClaims(string(d))
	if err != nil {
		return nil, err
	}
	ac, err := ctx.StoreCtx().Store.ReadAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		return nil, err
	}
	v := NewUserDescriber(*uc).Describe()
	if s, ok := ac.SigningKeys.GetScope(uc.Issuer); ok && s != nil {
		v = fmt.Sprintf("%s\n%s", v, NewScopedSkDescriber(s.(*jwt.UserScope)).Describe())
	}
	if IsStdOut(p.outputFile) {
		_, err = fmt.Fprintln(ctx.CurrentCmd().OutOrStdout(), v)
	} else {
		err = WriteFile(p.outputFile, []byte(v))
	}
	if err != nil {
		return nil, err
	}
	if !IsStdOut(p.outputFile) {
		k := "description"
		if Raw {
			k = "jwt"
		}
		return store.OKStatus("wrote %s %s to %#q", string(p.kind), k, AbbrevHomePaths(p.outputFile)), nil
	}
	return nil, nil
}
