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
	name       string
	outputFile string
	claim      jwt.OperatorClaims
	raw        []byte
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

func (p *DescribeOperatorParams) PreInteractive(_ ActionCtx) error {
	return nil
}

func (p *DescribeOperatorParams) Load(ctx ActionCtx) error {
	var err error
	if Json || Raw || JsonPath != "" {
		p.raw, err = ctx.StoreCtx().Store.ReadRawOperatorClaim()
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
		oc, err := ctx.StoreCtx().Store.ReadOperatorClaim()
		if err != nil {
			return err
		}
		p.claim = *oc
	}
	return nil
}

func (p *DescribeOperatorParams) Validate(_ ActionCtx) error {
	return nil
}

func (p *DescribeOperatorParams) PostInteractive(_ ActionCtx) error {
	return nil
}

func (p *DescribeOperatorParams) Run(_ ActionCtx) (store.Status, error) {
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
		v := NewOperatorDescriber(p.claim).Describe()
		data := []byte(v)
		if err := Write(p.outputFile, data); err != nil {
			return nil, err
		}
	}
	var s store.Status
	if !IsStdOut(p.outputFile) {
		k := "description"
		if Raw {
			k = "jwt"
		}
		s = store.OKStatus("wrote operator %s to %#q", k, AbbrevHomePaths(p.outputFile))
	}
	return s, nil
}
