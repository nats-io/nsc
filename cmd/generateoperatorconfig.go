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

	"github.com/nats-io/nsc/cli"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createGenerateOperatorConfigCmd() *cobra.Command {
	var params GenerateOperatorConfigParams
	cmd := &cobra.Command{
		Use:          "operator",
		Short:        "Generate an operator config",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		Hidden:       true,
		Example:      `nsc generate operator --n a`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunMaybeStorelessAction(cmd, args, &params); err != nil {
				return err
			}
			if !QuietMode() && params.out != "--" {
				cmd.Printf("Success!! - generated %q\n", params.out)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.name, "name", "n", "", "operator name")
	cmd.Flags().StringVarP(&params.out, "output-file", "o", "--", "output file '--' is stdout")

	return cmd
}

func init() {
	generateCmd.AddCommand(createGenerateOperatorConfigCmd())
}

type GenerateOperatorConfigParams struct {
	name string
	out  string
}

func (p *GenerateOperatorConfigParams) SetDefaults(ctx ActionCtx) error {
	if p.name == "" {
		p.name = GetConfig().Operator
	}
	return nil
}

func (p *GenerateOperatorConfigParams) PreInteractive(ctx ActionCtx) error {
	config := GetConfig()
	names := config.ListOperators()

	if len(names) == 0 {
		return fmt.Errorf("%q has no operators", config.StoreRoot)
	}

	if len(names) == 1 {
		p.name = names[0]
	}
	if len(names) > 1 {
		i, err := cli.PromptChoices("select operator", config.Operator, names)
		if err != nil {
			return err
		}
		p.name = names[i]
	}
	return nil
}

func (p *GenerateOperatorConfigParams) Load(ctx ActionCtx) error {
	return nil
}

func (p *GenerateOperatorConfigParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *GenerateOperatorConfigParams) Validate(ctx ActionCtx) error {
	if p.name == "" {
		return fmt.Errorf("name is required")
	}

	return nil
}

func (p *GenerateOperatorConfigParams) Run(_ ActionCtx) error {
	config := GetConfig()
	s, err := config.LoadStore(p.name)
	if err != nil {
		return err
	}

	name := s.GetName()
	d, err := s.Read(store.JwtName(name))
	if err != nil {
		return err
	}

	ctx, err := s.GetContext()
	if err != nil {
		return err
	}
	kp, err := ctx.KeyStore.GetOperatorKey(name)
	if err != nil {
		return err
	}
	if kp == nil {
		return fmt.Errorf("key for %q was not found", name)
	}
	seed, err := kp.Seed()
	if err != nil {
		return err
	}

	v := FormatConfig("Operator", string(d), string(seed))
	return Write(p.out, v)
}
