/*
 * Copyright 2018-2019 The NATS Authors
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
	"net/url"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cli"
	"github.com/spf13/cobra"
)

func createDescribeJwtCmd() *cobra.Command {
	var params DescribeFile
	var cmd = &cobra.Command{
		Use:          "jwt",
		Short:        "Describe a jwt file",
		Args:         MaxArgs(0),
		Example:      fmt.Sprintf(`%s describe jwt -f pathorurl`, GetToolName()),
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
	describeCmd.AddCommand(createDescribeJwtCmd())
	// creds cmd is the same as jwt, but to make it show in help we need to add it again
	creds := createDescribeJwtCmd()
	creds.Use = "creds"
	creds.Short = "Describe a creds file"
	creds.Example = fmt.Sprintf(`%s describe creds -f pathorurl`, GetToolName())
	creds.Flag("file").Usage = "a creds file"
	describeCmd.AddCommand(creds)
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
	if p.file == "" {
		ctx.CurrentCmd().SilenceErrors = false
		ctx.CurrentCmd().SilenceUsage = false
		return errors.New("file is required")
	}
	if u, err := url.Parse(p.file); err == nil && u.Scheme != "" {
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
		var ok bool
		p.token, ok = ExtractToken(string(d))
		if !ok {
			return fmt.Errorf("unable to extract JWT from %q", p.file)
		}
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
	case jwt.UserClaim:
		uc, err := jwt.DecodeUserClaims(p.token)
		if err != nil {
			return err
		}
		describer = NewUserDescriber(*uc)
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
