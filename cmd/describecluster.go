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

func createDescribeClusterCmd() *cobra.Command {
	var params DescribeClusterParams
	cmd := &cobra.Command{
		Use:          "cluster",
		Short:        "Describes a cluster",
		Args:         cobra.MaximumNArgs(0),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}
			if !IsStdOut(params.outputFile) {
				cmd.Printf("Success! - wrote cluster description to %q\n", params.outputFile)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.outputFile, "output-file", "o", "--", "output file, '--' is stdout")

	params.ClusterContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	describeCmd.AddCommand(createDescribeClusterCmd())
}

type DescribeClusterParams struct {
	ClusterContextParams
	jwt.ClusterClaims
	outputFile string
	token      string
}

func (p *DescribeClusterParams) SetDefaults(ctx ActionCtx) error {
	p.ClusterContextParams.SetDefaults(ctx)
	return nil
}

func (p *DescribeClusterParams) PreInteractive(ctx ActionCtx) error {
	return p.ClusterContextParams.Edit(ctx)
}

func (p *DescribeClusterParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.ClusterContextParams.Validate(ctx); err != nil {
		return err
	}

	if !ctx.StoreCtx().Store.Has(store.Clusters, p.ClusterContextParams.Name, store.JwtName(p.ClusterContextParams.Name)) {
		return fmt.Errorf("cluster %q is not defined in the current context", p.ClusterContextParams.Name)
	}
	ac, err := ctx.StoreCtx().Store.ReadClusterClaim(p.ClusterContextParams.Name)
	if err != nil {
		return err
	}
	if ac != nil {
		p.ClusterClaims = *ac
	}
	return nil
}

func (p *DescribeClusterParams) Validate(ctx ActionCtx) error {
	return nil
}

func (p *DescribeClusterParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *DescribeClusterParams) Run(ctx ActionCtx) error {
	v := NewClusterDescriber(p.ClusterClaims).Describe()
	return Write(p.outputFile, []byte(v))
}
