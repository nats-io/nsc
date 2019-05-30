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
	"os"
	"path/filepath"

	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createServerConfigCmd() *cobra.Command {
	var params GenerateServerConfigParams
	cmd := &cobra.Command{
		Use:          "config",
		Short:        "Generate an account config file for an operator",
		Args:         MaxArgs(0),
		SilenceUsage: true,
		Example:      `nsc generate config`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}
			if !QuietMode() && params.configOut != "--" {
				cmd.Printf("Success!! - generated %q\n", params.configOut)
				if params.operatorOut != "" && params.operatorOut != "--" {
					cmd.Printf("            generated %q\n", params.operatorOut)
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&params.nkeyConfig, "nkey", "", false, "generates an nkey account server configuration")
	cmd.Flags().MarkHidden("nkey")
	cmd.Flags().BoolVarP(&params.memResolverConfig, "mem-resolver", "", false, "generates a mem resolver server configuration")
	cmd.Flags().StringVarP(&params.operatorOut, "operator-jwt", "", "", "output operator jwt '--' is standard output (mem-resolver only)")
	cmd.Flags().StringVarP(&params.configOut, "config-file", "", "--", "output configuration file '--' is standard output")
	cmd.Flags().BoolVarP(&params.force, "force", "F", false, "overwrite output files if they exist")

	return cmd
}

func init() {
	generateCmd.AddCommand(createServerConfigCmd())
}

type GenerateServerConfigParams struct {
	operatorOut       string
	configOut         string
	force             bool
	nkeyConfig        bool
	memResolverConfig bool
	generator         ServerConfigGenerator
}

func (p *GenerateServerConfigParams) SetDefaults(ctx ActionCtx) error {
	if ctx.NothingToDo("nkey", "mem-resolver") {
		ctx.CurrentCmd().SilenceUsage = false
		return fmt.Errorf("specify a config type option")
	}
	if p.operatorOut != "" && p.nkeyConfig {
		ctx.CurrentCmd().SilenceUsage = false
		return fmt.Errorf("operator is not valid with nkey configuration")
	}
	if p.nkeyConfig {
		p.generator = NewNKeyConfigBuilder()
	} else if p.memResolverConfig {
		p.generator = NewMemResolverConfigBuilder()
	}
	return nil
}

func (p *GenerateServerConfigParams) PreInteractive(ctx ActionCtx) error {
	return nil
}

func (p *GenerateServerConfigParams) Load(ctx ActionCtx) error {
	return nil
}

func (p *GenerateServerConfigParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *GenerateServerConfigParams) checkFile(fp string) (string, error) {
	if fp == "--" {
		return fp, nil
	}
	afp, err := filepath.Abs(fp)
	if err != nil {
		return "", fmt.Errorf("error calculating abs %q: %v", fp, err)
	}
	_, err = os.Stat(afp)
	if err == nil {
		// file exists, if force - delete it
		if p.force {
			if err := os.Remove(afp); err != nil {
				return "", err
			}
			return afp, nil
		}
		return "", fmt.Errorf("%q already exists", afp)
	}
	return afp, nil
}

func (p *GenerateServerConfigParams) Validate(ctx ActionCtx) error {
	if p.memResolverConfig {
		if p.configOut == "--" && p.operatorOut != "--" || p.configOut != "--" && p.operatorOut == "--" {
			return fmt.Errorf("operator-jwt and config-file have to both be to stdout '--' or point to files")
		}
	}

	var err error
	if p.configOut != "" {
		p.configOut, err = p.checkFile(p.configOut)
		if err != nil {
			return err
		}
	}

	if p.operatorOut != "" {
		p.operatorOut, err = p.checkFile(p.operatorOut)
		if err != nil {
			return err
		}
	}

	if ctx.StoreCtx().Operator.Name == "" {
		return errors.New("set an operator first - 'nsc env --operator <name>'")
	}
	return nil
}

func (p *GenerateServerConfigParams) Run(ctx ActionCtx) error {
	s := ctx.StoreCtx().Store

	names, err := GetConfig().ListAccounts()
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return fmt.Errorf("operator %q has no accounts", GetConfig().Operator)
	}

	for _, n := range names {
		d, err := s.Read(store.Accounts, n, store.JwtName(n))
		if err != nil {
			return err
		}
		p.generator.Add(d)

		users, err := s.ListEntries(store.Accounts, n, store.Users)
		for _, u := range users {
			d, err := s.Read(store.Accounts, n, store.Users, store.JwtName(u))
			if err != nil {
				return err
			}
			p.generator.Add(d)
		}
	}

	if p.operatorOut != "" {
		d, err := s.Read(store.JwtName(s.GetName()))
		if err != nil {
			return err
		}
		if p.operatorOut == "--" {
			if err := Write("--", []byte("-----BEGIN NATS OPERATOR JWT-----\n")); err != nil {
				return err
			}
		}
		if err := Write(p.operatorOut, d); err != nil {
			return err
		}
		if p.operatorOut == "--" {
			if err := Write("--", []byte("\n------END NATS OPERATOR JWT------\n")); err != nil {
				return err
			}
		}
	}

	d, err := p.generator.Generate(p.operatorOut)
	if err != nil {
		return err
	}
	// if operator and config to stdout, add a header
	if p.operatorOut == "--" && p.configOut == "--" {
		if err := Write("--", []byte("-----BEGIN SERVER CONFIG -----\n")); err != nil {
			return err
		}
	}
	if err := Write(p.configOut, d); err != nil {
		return err
	}
	// if operator and config to stdout, add a header
	if p.operatorOut == "--" && p.configOut == "--" {
		if err := Write("--", []byte("------END SERVER CONFIG ------\n")); err != nil {
			return err
		}
	}
	return nil
}

type ServerConfigGenerator interface {
	Add(rawClaim []byte) error
	Generate(operatorPath string) ([]byte, error)
}
