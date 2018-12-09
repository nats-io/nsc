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
	"errors"
	"fmt"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createDescribeOperatorCmd() *cobra.Command {
	var params DescribeOperatorParams
	cmd := &cobra.Command{
		Use:          "operator",
		Short:        "Describes the operator",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunMaybeStorelessAction(cmd, args, &params); err != nil {
				return err
			}
			if !IsStdOut(params.outputFile) {
				cmd.Printf("Success! - wrote operator description to %q\n", params.outputFile)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.outputFile, "output-file", "o", "--", "output file, '--' is stdout")
	cmd.Flags().StringVarP(&params.name, "operator", "r", "", "operator name")

	return cmd
}

func init() {
	describeCmd.AddCommand(createDescribeOperatorCmd())
}

type DescribeOperatorParams struct {
	name       string
	outputFile string
	claim      jwt.OperatorClaims
}

func (p *DescribeOperatorParams) SetDefaults(ctx ActionCtx) error {
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

func (p *DescribeOperatorParams) PreInteractive(ctx ActionCtx) error {
	return nil
}

func (p *DescribeOperatorParams) Load(ctx ActionCtx) error {
	var err error

	name := ctx.StoreCtx().Store.GetName()
	if !ctx.StoreCtx().Store.Has(store.JwtName(name)) {
		return fmt.Errorf("no operator %q found", name)
	}

	d, err := ctx.StoreCtx().Store.Read(store.JwtName(name))
	if err != nil {
		return err
	}

	oc, err := jwt.DecodeOperatorClaims(string(d))
	if err != nil {
		return err
	}

	p.claim = *oc
	return nil
}

func (p *DescribeOperatorParams) Validate(ctx ActionCtx) error {
	return nil
}

func (p *DescribeOperatorParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *DescribeOperatorParams) Run(ctx ActionCtx) error {
	v := NewOperatorDescriber(p.claim).Describe()
	return Write(p.outputFile, []byte(v))
}
