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

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/spf13/cobra"
)

func createDescribeJwtCmd() *cobra.Command {
	var params DescribeFile
	var cmd = &cobra.Command{
		Use:          "jwt",
		Short:        "Describe a jwt/creds file",
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
}

type DescribeFile struct {
	file string
	BaseDescribe
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
	var err error
	if p.file == "" {
		ctx.CurrentCmd().SilenceErrors = false
		ctx.CurrentCmd().SilenceUsage = false
		return errors.New("file is required")
	}
	p.raw, err = LoadFromFileOrURL(p.file)
	if err != nil {
		return err
	}
	return p.Init()
}

func (p *DescribeFile) Validate(_ ActionCtx) error {
	return nil
}

func (p *DescribeFile) PostInteractive(_ ActionCtx) error {
	return nil
}

func (p *DescribeFile) Run(ctx ActionCtx) (store.Status, error) {
	return p.Describe(ctx)
}
