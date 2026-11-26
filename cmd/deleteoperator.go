// Copyright 2025 The NATS Authors
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
	"os"
	"path/filepath"

	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
)

func createDeleteOperatorCmd() *cobra.Command {
	var params DeleteOperatorParams
	cmd := &cobra.Command{
		Use:   "operator",
		Short: "Delete an operator, associated accounts and users",
		Args:  cobra.MaximumNArgs(1),
		Example: `nsc delete operator -n name
nsc delete operator -i
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().BoolVarP(&params.force, "force", "F", false, "overwrite the backup file")
	cmd.Flags().StringVarP(&params.name, "name", "n", "", "operator name")
	cmd.Flags().StringVarP(&params.backup, "backup", "", "", "backup file")

	return cmd
}

func init() {
	deleteCmd.AddCommand(createDeleteOperatorCmd())
}

type DeleteOperatorParams struct {
	name   string
	backup string
	force  bool
}

func (p *DeleteOperatorParams) SetDefaults(ctx ActionCtx) error {
	if p.backup == "" {
		fmt.Println(">>>>>", p.backup)
		return errors.New("backup file is required")
	}
	_, err := os.Stat(p.backup)
	if err == nil && !p.force {
		return fmt.Errorf("%s exists - --force is required", p.backup)
	}

	p.name = NameFlagOrArgument(p.name, ctx)
	if p.name == "" {
		p.name = ctx.StoreCtx().Operator.Name
	}
	if p.name != ctx.StoreCtx().Operator.Name {
		current := GetConfig()
		fp := filepath.Join(current.StoreRoot, p.name)
		sto, err := store.LoadStore(fp)
		if err != nil {
			return err
		}
		ctx.StoreCtx().Store = sto
	}
	return nil
}

func (p *DeleteOperatorParams) PreInteractive(_ ActionCtx) error {
	return nil
}

func (p *DeleteOperatorParams) Load(_ ActionCtx) error {
	return nil
}
func (p *DeleteOperatorParams) PostInteractive(_ ActionCtx) error {
	return nil
}

func (p *DeleteOperatorParams) Validate(_ ActionCtx) error {
	return nil
}

func (p *DeleteOperatorParams) Run(ctx ActionCtx) (store.Status, error) {
	status, err := ExportEnvironment(ctx, p.backup)
	if err != nil {
		return status, err
	}
	r, ok := status.(*store.Report)
	if !ok {
		return status, errors.New("unable to cast to report")
	}
	r.AddOK("exported environment to %s", p.backup)

	var files []string
	s := ctx.StoreCtx().Store
	ks := ctx.StoreCtx().KeyStore

	fn := s.Resolve(store.JwtName(s.GetName()))
	if s.Has(fn) {
		files = append(files, fn)
	} else {
		r.AddWarning("%s not found", fn)
	}
	oKeys, err := ctx.StoreCtx().GetOperatorKeys()
	if err != nil {
		r.AddError("error getting operator keys: %v", err.Error())
		return status, err
	}
	for _, k := range oKeys {
		if ks.HasPrivateKey(k) {
			files = append(files, ks.GetKeyPath(k))
		} else {
			r.AddWarning("operator key %s is not stured", k)
		}
	}

	accounts, err := ctx.StoreCtx().Store.ListSubContainers(store.Accounts)
	if err != nil {
		r.AddError("error listing accounts: %v", err.Error())
		return r, err
	}
	if len(accounts) == 0 {
		r.AddOK("no accounts found")
	} else {
		for _, a := range accounts {
			if s.Has(store.Accounts, a, store.JwtName(a)) {
				files = append(files, s.Resolve(store.Accounts, a, store.JwtName(a)))
			} else {
				r.AddWarning("account %s jwt not found", a)
			}
			if aKeys, err := ctx.StoreCtx().GetAccountKeys(a); err != nil {
				r.AddError("error getting account keys: %v", err.Error())
				return r, err
			} else {
				for _, k := range aKeys {
					if ks.HasPrivateKey(k) {
						files = append(files, ks.GetKeyPath(k))
					} else {
						r.AddWarning("account %s  - %s private key is not stored", a, k)
					}
				}
			}

			users, err := ctx.StoreCtx().Store.ListEntries(store.Accounts, a, store.Users)
			if err != nil {
				r.AddError("error listing users: %v", err.Error())
				return r, err
			}
			if len(users) == 0 {
				r.AddOK("no users found")
			} else {
				for _, u := range users {
					uc, err := s.ReadUserClaim(a, u)
					if err != nil {
						r.AddWarning("unable to read user %s: %v", u, err)
					}
					if ks.HasPrivateKey(uc.Subject) {
						files = append(files, ks.GetKeyPath(uc.Subject))
					} else {
						r.AddWarning("user %s private key is not stored", u)
					}
					fp := ks.GetUserCredsPath(a, u)
					if _, err := os.Stat(fp); err != nil {
						r.AddWarning("user creds %s not found: %v", u, err)
					} else {
						files = append(files, fp)
					}
				}
			}
		}
	}

	for _, f := range files {
		fmt.Println(f)
	}

	return status, nil
}
