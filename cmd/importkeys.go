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

	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createImportKeysCmd() *cobra.Command {
	var params ImportKeysParams
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Imports all nkeys found in a directory",
		Long:  `Imports all nkeys found in a directory`,
		Example: `nsc import keys --dir <path>
nsc import keys --recursive --dir <path>
`,
		Args:         MaxArgs(0),
		SilenceUsage: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunMaybeStorelessAction(cmd, args, &params); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.Dir, "dir", "d", "", "directory to import keys from")
	cmd.Flags().BoolVarP(&params.Recurse, "recurse", "R", false, "recurse directories")
	cmd.MarkFlagRequired("dir")

	return cmd
}

func init() {
	importCmd.AddCommand(createImportKeysCmd())
}

type ImportKeysParams struct {
	Dir     string
	Recurse bool
}

func (p *ImportKeysParams) SetDefaults(ctx ActionCtx) error {
	return nil
}

func (p *ImportKeysParams) PreInteractive(ctx ActionCtx) error {
	return nil
}

func (p *ImportKeysParams) Load(ctx ActionCtx) error {
	return nil
}

func (p *ImportKeysParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *ImportKeysParams) Validate(ctx ActionCtx) error {
	var err error
	p.Dir, err = Expand(p.Dir)
	if err != nil {
		return err
	}

	fi, err := os.Stat(p.Dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%#q is not a directory", p.Dir)
	}
	return nil
}

func (p *ImportKeysParams) Run(ctx ActionCtx) (store.Status, error) {
	var a []*ImportNKeyJob
	ks := ctx.StoreCtx().KeyStore
	ctx.CurrentCmd().SilenceUsage = true
	err := filepath.Walk(p.Dir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() && path != p.Dir && !p.Recurse {
			return filepath.SkipDir
		}
		ext := filepath.Ext(info.Name())
		if ext == ".nk" {
			var j ImportNKeyJob
			a = append(a, &j)
			j.filepath = path
			j.keypair, j.err = ks.Read(path)
			if j.err != nil {
				return nil
			}
			j.description, j.err = j.keypair.PublicKey()
			if j.err != nil {
				return nil
			}
			_, j.err = j.keypair.Seed()
			if j.err != nil {
				return nil
			}
			_, j.err = ks.Store(j.keypair)
		}
		return nil
	})

	if len(a) == 0 {
		return nil, errors.New("no nkey (.nk) files found")
	}
	r := store.NewDetailedReport(true)
	for _, j := range a {
		if j.err != nil {
			r.AddError("failed to import %#q: %v", j.filepath, j.err)
			continue
		} else {
			r.AddOK("%s was added to the keystore", j.description)
		}
	}
	return r, err
}

type ImportNKeyJob struct {
	description string
	filepath    string
	keypair     nkeys.KeyPair
	err         error
}
