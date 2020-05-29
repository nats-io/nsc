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
		Example: `nsc generate config --mem-resolver
nsc generate config --mem-resolver --config-file <outfile>
nsc generate config --mem-resolver --config-file <outfile> --force
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}
			if !QuietMode() && params.outputFile != "" && params.outputFile != "--" {
				cmd.Printf("Success!! - generated %#q\n", AbbrevHomePaths(params.outputFile))
			}
			if !QuietMode() && params.dirOut != "" {
				cmd.Printf("Success!! - generated  %#q\n", AbbrevHomePaths(filepath.Join(params.dirOut, "resolver.conf")))
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&params.nkeyConfig, "nkey", "", false, "generates an nkey account server configuration")
	cmd.Flags().BoolVarP(&params.memResolverConfig, "mem-resolver", "", false, "generates a mem resolver server configuration")
	cmd.Flags().StringVarP(&params.outputFile, "config-file", "", "--", "output configuration file '--' is standard output (exclusive of --dir)")
	cmd.Flags().StringVarP(&params.dirOut, "dir", "", "", "output configuration dir (only valid when --mem-resolver is specified)")
	cmd.Flags().BoolVarP(&params.force, "force", "F", false, "overwrite output files if they exist")
	cmd.Flags().StringVarP(&params.sysAccount, "sys-account", "", "", "system account name")
	cmd.Flags().MarkHidden("nkey")
	cmd.Flags().MarkHidden("dir")
	return cmd
}

func init() {
	generateCmd.AddCommand(createServerConfigCmd())
}

type GenerateServerConfigParams struct {
	sysAccount        string
	dirOut            string
	outputFile        string
	force             bool
	nkeyConfig        bool
	memResolverConfig bool
	generator         ServerConfigGenerator
}

func (p *GenerateServerConfigParams) SetDefaults(ctx ActionCtx) error {
	if ctx.NothingToDo("nkey", "mem-resolver", "dir") {
		ctx.CurrentCmd().SilenceUsage = false
		return fmt.Errorf("specify a config type option")
	}

	if p.dirOut != "" && p.nkeyConfig {
		ctx.CurrentCmd().SilenceUsage = false
		return fmt.Errorf("--dir is not valid with nkey configuration")
	}

	if p.dirOut != "" && p.outputFile != "--" {
		ctx.CurrentCmd().SilenceUsage = false
		return fmt.Errorf("--dir is exclusive of --config-file")
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
	afp, err := Expand(fp)
	if err != nil {
		return "", err
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
		return "", fmt.Errorf("%#q already exists", afp)
	}
	return afp, nil
}

func (p *GenerateServerConfigParams) checkDir(fp string) (string, error) {
	if fp == "--" {
		return fp, nil
	}
	afp, err := Expand(fp)
	if err != nil {
		return "", err
	}

	fi, err := os.Stat(afp)
	if err == nil {
		if !p.force {
			return "", fmt.Errorf("%#q already exists", fp)
		}
		// file exists, if force - delete it
		if !fi.IsDir() {
			return "", fmt.Errorf("%#q already exists and is not a directory", fp)
		}
	}
	return afp, nil
}

func (p *GenerateServerConfigParams) Validate(ctx ActionCtx) error {
	var err error
	if p.outputFile != "" {
		p.outputFile, err = p.checkFile(p.outputFile)
		if err != nil {
			return err
		}
	}
	if p.dirOut != "" {
		p.dirOut, err = p.checkDir(p.dirOut)
		if err != nil {
			return err
		}
		if err := p.generator.SetOutputDir(p.dirOut); err != nil {
			return err
		}
	}

	if p.sysAccount != "" {
		ac, err := ctx.StoreCtx().Store.ReadAccountClaim(p.sysAccount)
		if err != nil {
			return fmt.Errorf("error reading account %q: %v", p.sysAccount, err)
		}
		if err := p.generator.SetSystemAccount(ac.Subject); err != nil {
			return err
		}
	}

	if ctx.StoreCtx().Operator.Name == "" {
		return errors.New("set an operator first - 'nsc env --operator <name>'")
	}
	return nil
}

func (p *GenerateServerConfigParams) Run(ctx ActionCtx) (store.Status, error) {
	s := ctx.StoreCtx().Store

	op, err := s.Read(store.JwtName(s.GetName()))
	if err != nil {
		return nil, err
	}
	p.generator.Add(op)

	names, err := GetConfig().ListAccounts()
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("operator %q has no accounts", GetConfig().Operator)
	}

	for _, n := range names {
		d, err := s.Read(store.Accounts, n, store.JwtName(n))
		if err != nil {
			return nil, err
		}
		p.generator.Add(d)

		users, err := s.ListEntries(store.Accounts, n, store.Users)
		if err != nil {
			return nil, err
		}
		for _, u := range users {
			d, err := s.Read(store.Accounts, n, store.Users, store.JwtName(u))
			if err != nil {
				return nil, err
			}
			p.generator.Add(d)
		}
	}

	d, err := p.generator.Generate()
	if err != nil {
		return nil, err
	}
	if err := Write(p.outputFile, d); err != nil {
		return nil, err
	}
	if !IsStdOut(p.outputFile) {
		return store.OKStatus("wrote server configuration to %#q", AbbrevHomePaths(p.outputFile)), nil
	}
	return nil, err
}

type ServerConfigGenerator interface {
	Add(rawClaim []byte) error
	Generate() ([]byte, error)
	SetOutputDir(fp string) error
	SetSystemAccount(pubkey string) error
}
