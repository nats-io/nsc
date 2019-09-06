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
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createMigrateCmd() *cobra.Command {
	var params MigrateCmdParams
	var storeDir string
	var cmd = &cobra.Command{
		Hidden: true,

		Short:   "Migrate an account to the current operator",
		Example: "migrate --url <path or url to account jwt>",
		Use:     `migrate`,
		Args:    MaxArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if params.url != "" && storeDir != "" {
				return fmt.Errorf("specify one of --url or --store-dir")
			}
			var all []MigrateCmdParams
			if InteractiveFlag {
				ok, err := cli.PromptYN("migrate all accounts under a particular operator")
				if err != nil {
					return err
				}
				if ok {
					storeDir, err = cli.Prompt("specify the directory for the operator", "", true, func(v string) error {
						_, err := store.LoadStore(v)
						return err
					})
					if err != nil {
						return err
					}
				}
			}
			if storeDir != "" {
				storeDir, err = Expand(storeDir)
				if err != nil {
					return err
				}
				s, err := store.LoadStore(storeDir)
				if err != nil {
					return fmt.Errorf("error loading operator %q: %v", storeDir, err)
				}
				names, err := s.ListSubContainers(store.Accounts)
				if err != nil {
					return fmt.Errorf("error listing accounts in %q: %v", storeDir, err)
				}
				for _, n := range names {
					fp := filepath.Join(storeDir, store.Accounts, n, store.JwtName(n))
					var ip MigrateCmdParams
					ip.url = fp
					ip.overwrite = params.overwrite
					all = append(all, ip)
				}
			} else {
				all = append(all, params)
			}

			for _, p := range all {
				if err := RunAction(cmd, args, &p); err != nil {
					return err
				}

				m := fmt.Sprintf("migrated %q to operator %q", p.claim.Name, p.operator)
				um := fmt.Sprintf("%d users migrated", len(p.migratedUsers))
				if len(p.migratedUsers) == 0 {
					um = "no users migrated"
				}
				if !p.isFileImport {
					um = ""
				}
				cmd.Printf("%s [%s]\n", m, um)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.url, "url", "u", "", "path or url to import jwt from")
	cmd.Flags().StringVarP(&storeDir, "operator-dir", "", "", "path to an operator dir - all accounts are migrated")
	cmd.Flags().BoolVarP(&params.overwrite, "force", "F", false, "overwrite accounts with the same name")
	return cmd
}

func init() {
	GetRootCmd().AddCommand(createMigrateCmd())
}

type MigrateCmdParams struct {
	accountToken  string
	claim         *jwt.AccountClaims
	url           string
	isFileImport  bool
	operator      string
	migratedUsers []*jwt.UserClaims
	overwrite     bool
}

func (p *MigrateCmdParams) SetDefaults(ctx ActionCtx) error {
	return nil
}

func (p *MigrateCmdParams) PreInteractive(ctx ActionCtx) error {
	var err error
	p.url, err = cli.Prompt("account jwt url/or path ", p.url, true, func(v string) error {
		// we expect either a file or url
		if u, err := url.Parse(v); err == nil && u.Scheme != "" {
			return nil
		}
		v, err := Expand(v)
		if err != nil {
			return err
		}
		_, err = os.Stat(v)
		return err
	})
	return err
}

func (p *MigrateCmdParams) getAccountKeys() []string {
	var keys []string
	keys = append(keys, p.claim.Subject)
	keys = append(keys, p.claim.SigningKeys...)
	return keys
}

func (p *MigrateCmdParams) Load(ctx ActionCtx) error {
	if p.url == "" {
		return errors.New("an url or path to the account jwt is required")
	}
	data, err := LoadFromFileOrURL(p.url)
	if err != nil {
		return fmt.Errorf("error loading from %q: %v", p.url, err)
	}
	p.isFileImport = !IsURL(p.url)

	p.accountToken, err = jwt.ParseDecoratedJWT(data)
	if err != nil {
		return fmt.Errorf("error parsing JWT: %v", err)
	}
	p.claim, err = jwt.DecodeAccountClaims(p.accountToken)
	if err != nil {
		return fmt.Errorf("error decoding JWT: %v", err)
	}

	return nil
}

func (p *MigrateCmdParams) PostInteractive(ctx ActionCtx) error {
	if ctx.StoreCtx().Store.HasAccount(p.claim.Name) && !p.overwrite {
		aac, err := ctx.StoreCtx().Store.ReadAccountClaim(p.claim.Name)
		if err != nil {
			return err
		}
		p.overwrite = aac.Subject == p.claim.Subject
		if !p.overwrite {
			p.overwrite, err = cli.PromptBoolean("account %q already exists under the current operator, replace it", false)
		}
	}
	return nil
}

func (p *MigrateCmdParams) Validate(ctx ActionCtx) error {
	if p.isFileImport {
		parent := ctx.StoreCtx().Store.Dir
		// it is already determined to be a file
		fp, err := Expand(p.url)
		if err != nil {
			return err
		}
		if strings.HasPrefix(fp, parent) {
			return fmt.Errorf("cannot migrate %q onto itself", fp)
		}
	}

	if !p.overwrite && ctx.StoreCtx().Store.HasAccount(p.claim.Name) {
		return fmt.Errorf("account %q already exists, specify --force to overwrite", p.claim.Name)
	}

	return nil
}

func (p *MigrateCmdParams) Run(ctx ActionCtx) (store.Status, error) {
	ctx.CurrentCmd().SilenceUsage = true
	p.operator = ctx.StoreCtx().Operator.Name
	if ctx.StoreCtx().Store.IsManaged() {
		token, err := jwt.ParseDecoratedJWT([]byte(p.accountToken))
		if err != nil {
			return nil, err
		}
		ac, err := jwt.DecodeAccountClaims(token)
		if err != nil {
			return nil, err
		}
		var keys []string
		keys = append(keys, ac.Subject)
		keys = append(keys, ac.SigningKeys...)

		// need to sign it with any key we can get
		var kp nkeys.KeyPair
		for _, k := range keys {
			kp, _ = ctx.StoreCtx().KeyStore.GetKeyPair(k)
			if kp != nil {
				break
			}
		}
		if kp == nil {
			return nil, fmt.Errorf("unable to find any account keys - need any of %s", strings.Join(keys, ", "))
		}
		p.accountToken, err = ac.Encode(kp)
		if err != nil {
			return nil, err
		}
	}
	rs, err := ctx.StoreCtx().Store.StoreClaim([]byte(p.accountToken))
	if err != nil {
		return rs, err
	}

	if p.isFileImport {
		udir := filepath.Join(filepath.Dir(p.url), store.Users)
		fi, err := os.Stat(udir)
		if err == nil && fi.IsDir() {
			infos, err := ioutil.ReadDir(udir)
			if err != nil {
				return nil, err
			}
			for _, v := range infos {
				n := v.Name()
				if !v.IsDir() && filepath.Ext(n) == ".jwt" {
					up := filepath.Join(udir, n)
					d, err := Read(up)
					if err != nil {
						return nil, err
					}
					s, err := jwt.ParseDecoratedJWT(d)
					if err != nil {
						return nil, err
					}
					uc, err := jwt.DecodeUserClaims(s)
					if err := ctx.StoreCtx().Store.StoreRaw([]byte(s)); err != nil {
						return rs, err
					}
					p.migratedUsers = append(p.migratedUsers, uc)
				}
			}
		}
	}
	return rs, nil
}
