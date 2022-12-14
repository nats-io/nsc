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

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
)

func createDescribeJwtCmd() *cobra.Command {
	var params DescribeFile
	var cmd = &cobra.Command{
		Use:          "jwt",
		Short:        "Describe a jwt/creds file",
		Args:         MaxArgs(0),
		Example:      fmt.Sprintf(`%s describe -f pathorurl`, GetToolName()),
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
	p.file, err = cli.Prompt("token file or url", p.file)
	return err
}

func (p *DescribeFile) Load(ctx ActionCtx) error {
	if p.file == "" {
		ctx.CurrentCmd().SilenceErrors = false
		ctx.CurrentCmd().SilenceUsage = false
		return errors.New("file is required")
	}
	if d, err := LoadFromFileOrURL(p.file); err == nil {
		p.token, err = jwt.ParseDecoratedJWT(d)
		if err != nil {
			return err
		}
		gc, err := jwt.DecodeGeneric(p.token)
		if err != nil {
			return err
		}
		p.kind = gc.ClaimType()
	}
	return nil
}

func (p *DescribeFile) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *DescribeFile) Validate(ctx ActionCtx) error {
	return nil
}

func (p *DescribeFile) handleRaw() (store.Status, error) {
	var err error
	var raw []byte
	if Json || JsonPath != "" {
		raw, err = bodyAsJson([]byte(p.token))
		if err != nil {
			return nil, err
		}
		if JsonPath != "" {
			raw, err = GetField(raw, JsonPath)
			if err != nil {
				return nil, err
			}
		}
	}
	raw = append(raw, '\n')
	if err := Write(p.outputFile, raw); err != nil {
		return nil, err
	}
	var s store.Status
	if !IsStdOut(p.outputFile) {
		k := "description"
		if Raw {
			k = "jwt"
		}
		s = store.OKStatus("wrote jwt %s to %#q", k, AbbrevHomePaths(p.outputFile))
	}
	return s, nil
}

func (p *DescribeFile) Run(ctx ActionCtx) (store.Status, error) {
	if Json || Raw || JsonPath != "" {
		return p.handleRaw()
	}

	var describer Describer
	switch p.kind {
	case jwt.AccountClaim:
		ac, err := jwt.DecodeAccountClaims(p.token)
		if err != nil {
			return nil, err
		}
		describer = NewAccountDescriber(*ac)
	case jwt.ActivationClaim:
		ac, err := jwt.DecodeActivationClaims(p.token)
		if err != nil {
			return nil, err
		}
		describer = NewActivationDescriber(*ac)
	case jwt.UserClaim:
		uc, err := jwt.DecodeUserClaims(p.token)
		if err != nil {
			return nil, err
		}
		describer = NewUserDescriber(*uc)
	case jwt.OperatorClaim:
		oc, err := jwt.DecodeOperatorClaims(p.token)
		if err != nil {
			return nil, err
		}
		describer = NewOperatorDescriber(*oc)
	}

	if describer == nil {
		return nil, fmt.Errorf("describer for %q is not implemented", p.kind)
	}

	if err := Write(p.outputFile, []byte(describer.Describe())); err != nil {
		return nil, err
	}
	var s store.Status
	if !IsStdOut(p.outputFile) {
		s = store.OKStatus("wrote account description to %#q", AbbrevHomePaths(p.outputFile))
	}
	return s, nil
}
