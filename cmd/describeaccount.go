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
	"github.com/nats-io/nsc/v2/cmd/store"
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
	BaseDescribe
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
	p.raw, err = ctx.StoreCtx().Store.ReadRawAccountClaim(p.AccountContextParams.Name)
	if err != nil {
		return err
	}
	return p.Init()
}

func (p *DescribeAccountParams) Validate(ctx ActionCtx) error {
	return p.AccountContextParams.Validate(ctx)
}

func (p *DescribeAccountParams) PostInteractive(_ ActionCtx) error {
	return nil
}

func (p *DescribeAccountParams) Run(ctx ActionCtx) (store.Status, error) {
	return p.Describe(ctx)
}
