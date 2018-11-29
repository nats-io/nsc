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
	"net/url"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cli"
	"github.com/spf13/cobra"
)

var describeCmd *cobra.Command

func createDescribeCmd() *cobra.Command {
	var params DescribeFile
	var cmd = &cobra.Command{
		Use:   "describe",
		Short: "Describe assets such as accounts, users, activations, services, and streams",
		Example: `nsc describe -f pathorurl
nsc describe account
nsc describe account -n foo`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunStoreLessAction(cmd, args, &params); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.outputFile, "output-file", "o", "--", "output file, '--' is stdout")
	cmd.Flags().StringVarP(&params.file, "file", "f", "", "a token file or url to a token file")

	return cmd
}

func init() {
	describeCmd = createDescribeCmd()
	GetRootCmd().AddCommand(describeCmd)
}

type DescribeFile struct {
	file       string
	kind       jwt.ClaimType
	outputFile string
	token      string
}

func (p *DescribeFile) SetDefaults(ctx ActionCtx) error {
	return nil
}

func (p *DescribeFile) PreInteractive(ctx ActionCtx) error {
	var err error
	p.file, err = cli.Prompt("token file or url", p.file, true, func(s string) error {
		return nil
	})
	return err
}

func (p *DescribeFile) Load(ctx ActionCtx) error {
	if url, err := url.Parse(p.file); err == nil && url.Scheme != "" {
		d, err := LoadFromURL(p.file)
		if err != nil {
			return err
		}
		p.token = string(d)
	} else {
		d, err := Read(p.file)
		if err != nil {
			return err
		}
		p.token = ExtractToken(string(d))
	}

	gc, err := jwt.DecodeGeneric(p.token)
	if err != nil {
		return err
	}
	p.kind = gc.Type
	return nil
}

func (p *DescribeFile) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *DescribeFile) Validate(ctx ActionCtx) error {
	return nil
}

func (p *DescribeFile) Run(ctx ActionCtx) error {
	var describer Describer
	switch p.kind {
	case jwt.AccountClaim:
		ac, err := jwt.DecodeAccountClaims(p.token)
		if err != nil {
			return err
		}
		describer = NewAccountDescriber(*ac)
	case jwt.ActivationClaim:
		ac, err := jwt.DecodeActivationClaims(p.token)
		if err != nil {
			return err
		}
		describer = NewActivationDescriber(*ac)
	case jwt.ClusterClaim:
		cc, err := jwt.DecodeClusterClaims(p.token)
		if err != nil {
			return err
		}
		describer = NewClusterDescriber(*cc)
	case jwt.UserClaim:
		uc, err := jwt.DecodeUserClaims(p.token)
		if err != nil {
			return err
		}
		describer = NewUserDescriber(*uc)
	case jwt.ServerClaim:
		uc, err := jwt.DecodeServerClaims(p.token)
		if err != nil {
			return err
		}
		describer = NewServerDescriber(*uc)
	case jwt.OperatorClaim:
		oc, err := jwt.DecodeOperatorClaims(p.token)
		if err != nil {
			return err
		}
		describer = NewOperatorDescriber(*oc)
	}

	if describer == nil {
		return fmt.Errorf("describer for %q is not implemented", p.kind)
	}

	return Write(p.outputFile, []byte(describer.Describe()))
}
