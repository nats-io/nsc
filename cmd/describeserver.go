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

func createDescribeServerCmd() *cobra.Command {
	var params DescribeServerParams
	cmd := &cobra.Command{
		Use:          "server",
		Short:        "Describes a server",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}
			if !IsStdOut(params.outputFile) {
				cmd.Printf("Success! - wrote server description to %q\n", params.outputFile)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.outputFile, "output-file", "o", "--", "output file, '--' is stdout")
	cmd.Flags().StringVarP(&params.server, "server", "s", "", "server name")

	params.ClusterContextParams.BindFlags(cmd)

	return cmd
}

func init() {
	describeCmd.AddCommand(createDescribeServerCmd())
}

type DescribeServerParams struct {
	ClusterContextParams
	jwt.ServerClaims
	server     string
	outputFile string
	token      string
}

func (p *DescribeServerParams) SetDefaults(ctx ActionCtx) error {
	p.ClusterContextParams.SetDefaults(ctx)

	return nil
}

func (p *DescribeServerParams) PreInteractive(ctx ActionCtx) error {
	var err error

	if err = p.ClusterContextParams.Edit(ctx); err != nil {
		return err
	}
	if p.server == "" {
		p.server, err = ctx.StoreCtx().PickServer(p.ClusterContextParams.Name)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *DescribeServerParams) Load(ctx ActionCtx) error {
	var err error

	if err = p.ClusterContextParams.Validate(ctx); err != nil {
		return err
	}

	if p.server == "" {
		n := ctx.StoreCtx().DefaultServer(p.ClusterContextParams.Name)
		if n != nil {
			p.server = *n
		}
	}

	if p.server == "" {
		return fmt.Errorf("server is required")
	}

	if !ctx.StoreCtx().Store.Has(store.Clusters, p.ClusterContextParams.Name, store.Servers, store.JwtName(p.server)) {
		return fmt.Errorf("server %q not found", p.server)
	}

	us, err := ctx.StoreCtx().Store.ReadServerClaim(p.ClusterContextParams.Name, p.server)
	if err != nil {
		return err
	}
	if us != nil {
		p.ServerClaims = *us
	}
	return nil
}

func (p *DescribeServerParams) Validate(ctx ActionCtx) error {
	return nil
}

func (p *DescribeServerParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *DescribeServerParams) Run(ctx ActionCtx) error {
	v := NewServerDescriber(p.ServerClaims).Describe()
	return Write(p.outputFile, []byte(v))
}
