// Copyright 2018-2025 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"errors"
	"fmt"
	"github.com/nats-io/nsc/v2/cmd/store"

	"github.com/spf13/cobra"
)

func createDescribeOperatorCmd() *cobra.Command {
	var params DescribeOperatorParams
	cmd := &cobra.Command{
		Use:          "operator",
		Short:        "Describes the operator",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunMaybeStorelessAction(cmd, args, &params)
		},
	}
	cmd.Flags().StringVarP(&params.outputFile, "output-file", "o", "--", "output file, '--' is stdout")
	cmd.Flags().StringVarP(&params.name, "name", "n", "", "operator name")

	return cmd
}

func init() {
	describeCmd.AddCommand(createDescribeOperatorCmd())
}

type DescribeOperatorParams struct {
	name string
	BaseDescribe
}

func (p *DescribeOperatorParams) SetDefaults(ctx ActionCtx) error {
	p.name = NameFlagOrArgument(p.name, ctx)
	if p.name != "" {
		actx, ok := ctx.(*Actx)
		if !ok {
			return errors.New("unable to cast to actx")
		}
		s, err := GetStoreForOperator(p.name)
		if err != nil {
			return err
		}
		cc, err := s.GetContext()
		if err != nil {
			return err
		}
		actx.ctx.Store = s
		actx.ctx = cc
	} else if ctx.StoreCtx().Store == nil {
		return fmt.Errorf("set an operator")

	}
	return nil
}

func (p *DescribeOperatorParams) Load(ctx ActionCtx) error {
	var err error
	p.raw, err = ctx.StoreCtx().Store.ReadRawOperatorClaim()
	if err != nil {
		return err
	}
	return p.Init()
}

func (p *DescribeOperatorParams) PreInteractive(_ ActionCtx) error {
	return nil
}

func (p *DescribeOperatorParams) Validate(_ ActionCtx) error {
	return nil
}

func (p *DescribeOperatorParams) PostInteractive(_ ActionCtx) error {
	return nil
}

func (p *DescribeOperatorParams) Run(ctx ActionCtx) (store.Status, error) {
	return p.Describe(ctx)
}
