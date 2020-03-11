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
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createExportKeysCmd() *cobra.Command {
	var params ExportKeysParams
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Export operator, account and user keys in the current operator and account context",
		Long: `Export operator, account and user keys in the current operator and account context.
Additional flags allow you to specify which types of keys to export. For example
the --operator flag exports any operator keys, --accounts exports account keys, etc. 

To export all key types specify the --all flag.


You can limit export to a different account context by specifying --account flag.
You can limit exporting user keys to the specified user by specifying the --user flag.

The --not-referenced flag exports all keys not relevant to the current  operator, 
accounts and users. These keys may be referenced in a different  operator context.

The --filter flag allows you to specify a few letters in a public key and export only 
those keys that matching the filter (provided the key type matches --operator, --account,
--user (or --all).
`,
		Example: `nsc export keys --dir <path> (exports the current operator, account and users keys)
nsc export keys --operator --accounts --users (exports current operators, all accounts, and users)
nsc export keys --all (same as specifying --operator --accounts --users)
nsc export keys --operator --not-referenced (exports any other operator keys in the keystore)
nsc export keys --all --filter VSVMGA (exports all keys containing the filter)
nsc export keys --account <name> (changes the account context to the specified account)
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
	cmd.Flags().BoolVarP(&params.Operator, "operator", "o", false, "export operator keys")
	cmd.Flags().BoolVarP(&params.Accounts, "accounts", "a", false, "export account keys")
	cmd.Flags().BoolVarP(&params.Users, "users", "u", false, "export user keys")
	cmd.Flags().StringVarP(&params.Account, "account", "", "", "change account context to the named account")
	cmd.Flags().StringVarP(&params.User, "user", "", "", "export specified user key")
	cmd.Flags().BoolVarP(&params.All, "all", "A", false, "export operator, accounts and users keys")
	cmd.Flags().StringVarP(&params.Filter, "filter", "f", "", "export keys containing string")
	cmd.Flags().BoolVarP(&params.Unreferenced, "not-referenced", "", false, "export keys that are not referenced in the current operator context")
	cmd.Flags().StringVarP(&params.Dir, "dir", "d", "", "directory to export keys to")
	cmd.Flags().BoolVarP(&params.Force, "force", "F", false, "overwrite existing files")
	cmd.Flags().BoolVarP(&params.Remove, "remove", "R", false, "removes the original key file from the keyring after exporting it")
	cmd.MarkFlagRequired("dir")

	return cmd
}

func init() {
	exportCmd.AddCommand(createExportKeysCmd())
}

type ExportKeysParams struct {
	Force  bool
	Remove bool
	Dir    string
	KeyCollectorParams
}

func (p *ExportKeysParams) SetDefaults(ctx ActionCtx) error {
	return p.KeyCollectorParams.SetDefaults(ctx)
}

func (p *ExportKeysParams) PreInteractive(ctx ActionCtx) error {
	return nil
}

func (p *ExportKeysParams) Load(ctx ActionCtx) error {
	return nil
}

func (p *ExportKeysParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *ExportKeysParams) Validate(ctx ActionCtx) error {
	d := store.GetKeysDir()
	_, err := os.Stat(d)
	if os.IsNotExist(err) {
		return fmt.Errorf("keystore %#q does not exist", d)
	}
	return nil
}

func (p *ExportKeysParams) Run(ctx ActionCtx) (store.Status, error) {
	ctx.CurrentCmd().SilenceUsage = true

	var wj []ExportJob
	var err error
	var keys Keys

	ks := ctx.StoreCtx().KeyStore
	p.Dir, err = Expand(p.Dir)
	if err != nil {
		return nil, err
	}

	sr := store.NewDetailedReport(true)
	keys.KeyList, err = p.KeyCollectorParams.Run(ctx)
	for _, k := range keys.KeyList {
		var j ExportJob
		j.description = k.Pub
		if k.HasKey() {
			s, err := ks.GetSeed(k.Pub)
			if err != nil {
				sr.AddError("error reading seed for %s", k.Pub)
				continue
			}
			j.filepath = filepath.Join(p.Dir, fmt.Sprintf("%s.nk", k.Pub))
			_, err = os.Stat(j.filepath)
			if os.IsNotExist(err) || (err == nil && p.Force) {
				j.data = []byte(s)
			} else {
				sr.AddError("%#q already exists - specify --force to overwrite", j.filepath)
				continue
			}
		}
		wj = append(wj, j)
	}

	if keys.Len() == 0 {
		return nil, errors.New("no keys found to export")
	}

	if err := MaybeMakeDir(p.Dir); err != nil {
		return nil, err
	}

	for _, j := range wj {
		if j.filepath != "" {
			j.err = ioutil.WriteFile(j.filepath, j.data, 0700)
			if j.err != nil {
				sr.AddError("error exporting %q: %v", j.description, j.err)
			} else {
				if p.Remove {
					err := ks.Remove(j.description)
					if err != nil {
						sr.AddError("exported %q but failed to delete original file: %v", j.description, err)
						continue
					} else {
						sr.AddOK("moved %q", j.description)
						continue
					}
				}
				sr.AddOK("exported %q", j.description)
			}
		} else {
			sr.AddWarning("skipped %q - no seed available", j.description)
		}
	}
	return sr, err
}

type ExportJob struct {
	description string
	filepath    string
	data        []byte
	err         error
}
