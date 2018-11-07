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
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/nats-io/jwt"
	"github.com/spf13/cobra"
)

func createGenerateEnvCmd() *cobra.Command {
	var params GenerateEnvParams
	var cmd = &cobra.Command{
		Use:   "environment",
		Short: "Generate a runtime environment for a client",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := params.Validate(); err != nil {
				return err
			}
			if err := params.Run(); err != nil {
				return err
			}

			cmd.Printf("Success! - generated development environment in %q\n", params.outdir)
			if params.privateKey != "" {
				cmd.Printf("Success! - user private key stored in %q\n", filepath.Join(params.outdir, "private.key"))
			}
			if params.publicKey != "" {
				cmd.Printf("Success! - user public key stored in %q\n", filepath.Join(params.outdir, "public.key"))
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&params.outdir, "outdir", "o", "", "output directory where to create an environment - a directory named for the user will be created")
	cmd.Flags().StringVarP(&params.publicKey, "public-key", "k", "", "user public key")
	cmd.Flags().StringVarP(&params.privateKey, "private-key", "p", "", "private key for the user")
	cmd.Flags().StringVarP(&params.expiry, "expiry", "e", "30d", "expiry for jwt (default 30 days - specify '0' for no expiration) - supported patterns include: yyyy-mm-dd, n(m)inutes, n(h)ours, n(d)ays, n(w)eeks, n(M)onths, n(y)ears")

	cmd.MarkFlagRequired("outdir")

	return cmd
}

func init() {
	generateCmd.AddCommand(createGenerateEnvCmd())
}

type GenerateEnvParams struct {
	outdir     string
	privateKey string
	publicKey  string
	expiry     string
}

func (p *GenerateEnvParams) Validate() error {
	if !OkToWrite(p.outdir) {
		return fmt.Errorf("outdir %q exists", p.outdir)
	}

	u := User{}
	u.PublicKey = p.publicKey
	if err := u.Load(); err != nil {
		return err
	}

	return nil
}

func (p *GenerateEnvParams) Run() error {
	if err := os.MkdirAll(p.outdir, 0700); err != nil {
		return err
	}

	if p.privateKey != "" {
		pk := filepath.Join(p.outdir, "private.key")
		ioutil.WriteFile(pk, []byte(p.privateKey), 0600)
	}

	if p.publicKey != "" {
		pk := filepath.Join(p.outdir, "public.key")
		ioutil.WriteFile(pk, []byte(p.publicKey), 0600)
	}

	token := filepath.Join(p.outdir, "token.jwt")

	var args jwt.StringList
	args.Add("generate", "user", "--public-key", p.publicKey, "--output-file", token)
	if p.expiry != "" {
		args.Add("--expiry", p.expiry)
	}
	rootCmd.SetArgs(args)
	return rootCmd.Execute()
}
