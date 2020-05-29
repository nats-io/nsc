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
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

func createMigrateCmd() *cobra.Command {
	var params MigrateCmdParams
	var cmd = &cobra.Command{
		Hidden: true,

		Short:   "Migrate an account to the current operator",
		Example: "migrate --url <path or url to account jwt>",
		Use:     `migrate`,
		Args:    MaxArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&params.url, "url", "u", "", "path or url to import jwt from")
	cmd.Flags().StringVarP(&params.storeDir, "operator-dir", "", "", "path to an operator dir - all accounts are migrated")
	cmd.Flags().BoolVarP(&params.overwrite, "force", "F", false, "overwrite accounts with the same name")
	return cmd
}

func init() {
	GetRootCmd().AddCommand(createMigrateCmd())
}

type MigrateCmdParams struct {
	url       string
	storeDir  string
	overwrite bool
	Jobs      []*MigrateJob
}

func (p *MigrateCmdParams) SetDefaults(ctx ActionCtx) error {
	if p.url != "" && p.storeDir != "" {
		return fmt.Errorf("specify one of --url or --store-dir")
	}
	return nil
}

func (p *MigrateCmdParams) PreInteractive(ctx ActionCtx) error {
	ok, err := cli.Confirm("migrate all accounts under a particular operator", true)
	if err != nil {
		return err
	}
	if ok {
		p.storeDir, err = cli.Prompt("specify the directory for the operator", "", cli.Val(func(v string) error {
			_, err := store.LoadStore(v)
			return err
		}))
		if err != nil {
			return err
		}
	} else {
		p.url, err = cli.Prompt("account jwt url/or path ", p.url, cli.Val(func(v string) error {
			// we expect either a file or url
			if IsURL(v) {
				return nil
			}
			v, err := Expand(v)
			if err != nil {
				return err
			}
			_, err = os.Stat(v)
			return err
		}))
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *MigrateCmdParams) Load(ctx ActionCtx) error {
	var err error
	if p.storeDir != "" {
		p.storeDir, err = Expand(p.storeDir)
		if err != nil {
			return err
		}

		s, err := store.LoadStore(p.storeDir)
		if err != nil {
			return fmt.Errorf("error loading operator %#q: %v", p.storeDir, err)
		}
		names, err := s.ListSubContainers(store.Accounts)
		if err != nil {
			return fmt.Errorf("error listing accounts in %#q: %v", p.storeDir, err)
		}
		for _, n := range names {
			mj := NewMigrateJob(filepath.Join(p.storeDir, store.Accounts, n, store.JwtName(n)), p.overwrite)
			p.Jobs = append(p.Jobs, &mj)
		}
	} else {
		mj := NewMigrateJob(p.url, p.overwrite)
		p.Jobs = append(p.Jobs, &mj)
	}

	for _, j := range p.Jobs {
		j.Load(ctx)
	}
	return nil
}

func (p *MigrateCmdParams) PostInteractive(ctx ActionCtx) error {
	for _, j := range p.Jobs {
		if j.OK() {
			j.PostInteractive(ctx)
		}
	}
	return nil
}

func (p *MigrateCmdParams) Validate(ctx ActionCtx) error {
	for _, j := range p.Jobs {
		if j.OK() {
			j.Validate(ctx)
		}
	}
	return nil
}

func (p *MigrateCmdParams) Run(ctx ActionCtx) (store.Status, error) {
	var jobs store.MultiJob
	for _, j := range p.Jobs {
		if j.OK() {
			j.Run(ctx)
		}
		jobs = append(jobs, j.status)
	}
	m, err := jobs.Summary()
	if m != "" {
		ctx.CurrentCmd().Println(m)
	}
	return jobs, err
}

type MigrateJob struct {
	accountToken  string
	claim         *jwt.AccountClaims
	url           string
	isFileImport  bool
	operator      string
	migratedUsers []*jwt.UserClaims
	overwrite     bool

	status store.Status
}

func NewMigrateJob(url string, overwrite bool) MigrateJob {
	return MigrateJob{url: url, overwrite: overwrite, status: &store.Report{}}
}

func (j *MigrateJob) OK() bool {
	code := j.status.Code()
	return code == store.OK || code == store.NONE
}

func (j *MigrateJob) getAccountKeys() []string {
	var keys []string
	keys = append(keys, j.claim.Subject)
	keys = append(keys, j.claim.SigningKeys...)
	return keys
}

func (j *MigrateJob) Load(ctx ActionCtx) {
	if j.url == "" {
		j.status = store.ErrorStatus("an url or path to the account jwt is required")
		return
	}
	data, err := LoadFromFileOrURL(j.url)
	if err != nil {
		j.status = store.ErrorStatus(fmt.Sprintf("error loading from %#q: %v", j.url, err))
		return
	}
	j.isFileImport = !IsURL(j.url)

	j.accountToken, err = jwt.ParseDecoratedJWT(data)
	if err != nil {
		j.status = store.ErrorStatus(fmt.Sprintf("error parsing JWT: %v", err))
		return
	}
	j.claim, err = jwt.DecodeAccountClaims(j.accountToken)
	if err != nil {
		j.status = store.ErrorStatus(fmt.Sprintf("error decoding JWT: %v", err))
		return
	}
}

func (j *MigrateJob) PostInteractive(ctx ActionCtx) {
	if ctx.StoreCtx().Store.HasAccount(j.claim.Name) && !j.overwrite {
		aac, err := ctx.StoreCtx().Store.ReadAccountClaim(j.claim.Name)
		if err != nil {

			j.status = store.ErrorStatus(fmt.Sprintf("error reading account JWT: %v", err))
			return
		}
		j.overwrite = aac.Subject == j.claim.Subject
		if !j.overwrite {
			j.overwrite, err = cli.Confirm("account %q already exists under the current operator, replace it", false)
			if err != nil {
				j.status = store.ErrorStatus(fmt.Sprintf("%v", err))
				return
			}
		}
	}
}

func (j *MigrateJob) Validate(ctx ActionCtx) {
	if j.isFileImport {
		parent := ctx.StoreCtx().Store.Dir
		// it is already determined to be a file
		fp, err := Expand(j.url)
		if err != nil {
			j.status = store.ErrorStatus(fmt.Sprintf("%v", err))
			return
		}
		if strings.HasPrefix(fp, parent) {
			j.status = store.ErrorStatus(fmt.Sprintf("cannot migrate %q onto itself", fp))
			return
		}
	}

	if !j.overwrite && ctx.StoreCtx().Store.HasAccount(j.claim.Name) {
		j.status = store.ErrorStatus(fmt.Sprintf("account %q already exists, specify --force to overwrite", j.claim.Name))
		return
	}

	keys := j.getAccountKeys()
	var hasOne bool
	for _, k := range keys {
		kp, _ := ctx.StoreCtx().KeyStore.GetKeyPair(k)
		if kp != nil {
			hasOne = true
			break
		}
	}
	if !hasOne {
		j.status = store.ErrorStatus(fmt.Sprintf("unable to find an account key for %q - need one of %s", j.claim.Name, strings.Join(keys, ", ")))
		return
	}
}

func (j *MigrateJob) Run(ctx ActionCtx) {
	ctx.CurrentCmd().SilenceUsage = true
	j.operator = ctx.StoreCtx().Operator.Name

	token, err := jwt.ParseDecoratedJWT([]byte(j.accountToken))
	if err != nil {
		j.status = store.ErrorStatus(fmt.Sprintf("%v", err))
		return
	}
	ac, err := jwt.DecodeAccountClaims(token)
	if err != nil {
		j.status = store.ErrorStatus(fmt.Sprintf("%v", err))
		return
	}

	if ctx.StoreCtx().Store.IsManaged() {
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
			j.status = store.ErrorStatus(fmt.Sprintf("unable to find any account keys - need any of %s", strings.Join(keys, ", ")))
			return
		}
		j.accountToken, err = ac.Encode(kp)
		if err != nil {
			j.status = store.ErrorStatus(fmt.Sprintf("%v", err))
			return
		}
	}

	remote, err := ctx.StoreCtx().Store.StoreClaim([]byte(j.accountToken))
	if err != nil {
		j.status = store.ErrorStatus(fmt.Sprintf("failed to migrate %q: %v", ac.Name, err))
		return
	}

	if j.isFileImport {
		udir := filepath.Join(filepath.Dir(j.url), store.Users)
		fi, err := os.Stat(udir)
		if err == nil && fi.IsDir() {
			infos, err := ioutil.ReadDir(udir)
			if err != nil {
				j.status = store.ErrorStatus(fmt.Sprintf("%v", err))
				return
			}
			for _, v := range infos {
				n := v.Name()
				if !v.IsDir() && filepath.Ext(n) == ".jwt" {
					up := filepath.Join(udir, n)
					d, err := Read(up)
					if err != nil {
						j.status = store.ErrorStatus(fmt.Sprintf("%v", err))
						return
					}
					s, err := jwt.ParseDecoratedJWT(d)
					if err != nil {
						j.status = store.ErrorStatus(fmt.Sprintf("%v", err))
						return
					}
					uc, err := jwt.DecodeUserClaims(s)
					if err != nil {
						j.status = store.ErrorStatus(fmt.Sprintf("%v", err))
						return
					}
					if err := ctx.StoreCtx().Store.StoreRaw([]byte(s)); err != nil {
						j.status = store.ErrorStatus(fmt.Sprintf("%v", err))
						return
					}
					j.migratedUsers = append(j.migratedUsers, uc)
				}
			}
		}
	}

	m := fmt.Sprintf("migrated %q to operator %q", j.claim.Name, j.operator)
	um := fmt.Sprintf("%d users migrated", len(j.migratedUsers))
	if len(j.migratedUsers) == 0 {
		um = "no users migrated"
	}
	if !j.isFileImport {
		um = ""
	}

	j.status = store.OKStatus(fmt.Sprintf("%s [%s]", m, um))
	if remote != nil {
		si, ok := j.status.(*store.Report)
		if ok {
			si.Details = append(si.Details, remote)
		}
	}
}
