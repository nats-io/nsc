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
	"encoding/json"
	"fmt"
	"os"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
)

type ImportEnvironmentParams struct {
	in       string
	force    bool
	operator *Operator
	rename   string
	reissue  bool
}

func createImportEnvironment() *cobra.Command {
	var params ImportEnvironmentParams
	cmd := &cobra.Command{
		Use:          "environment",
		Short:        "import operator, accounts, users and keys",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunMaybeStorelessAction(cmd, args, &params)
		},
	}
	cmd.Flags().StringVarP(&params.in, "in", "", "", "input file")
	cmd.Flags().BoolVarP(&params.force, "force", "", false, "overwrite existing operator, possibly merging (not recommended)")
	cmd.Flags().StringVarP(&params.rename, "rename", "", "", "rename operator")
	cmd.Flags().BoolVarP(&params.reissue, "reissue", "", false, "regenerate all keys")
	return cmd
}

func init() {
	importCmd.AddCommand(createImportEnvironment())
}

func (p *ImportEnvironmentParams) SetDefaults(_ ActionCtx) error {
	return nil
}

func (p *ImportEnvironmentParams) PreInteractive(_ ActionCtx) error {
	return nil
}

func (p *ImportEnvironmentParams) Load(ctx ActionCtx) error {
	if p.in == "" {
		return fmt.Errorf("specify an input file")
	}
	data, err := os.ReadFile(p.in)
	if err != nil {
		return err
	}

	var env Environment
	if err := json.Unmarshal(data, &env); err != nil {
		return err
	}

	if len(env.Operators) == 0 {
		return fmt.Errorf("no operators in the input file")
	}

	if len(env.Operators) > 1 {
		return fmt.Errorf("only one operator may be imported")
	}

	p.operator = env.Operators[0]
	if p.operator.Name == "" || p.operator.Jwt == "" {
		return fmt.Errorf("invalid input file, operator name/jwt required")
	}

	operators := config.ListOperators()
	found := false
	for _, o := range operators {
		if o == p.operator.Name {
			found = true
			break
		}
	}
	if found && (!p.force && p.rename == "") {
		return fmt.Errorf("operator %s already exist, '--force' to overwrite after creating a backup or '--rename", p.operator.Name)
	}
	return nil
}

func (p *ImportEnvironmentParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *ImportEnvironmentParams) Validate(ctx ActionCtx) error {
	return nil
}

func (p *ImportEnvironmentParams) Run(ctx ActionCtx) (store.Status, error) {
	r := store.NewDetailedReport(true)

	oc, err := jwt.DecodeOperatorClaims(p.operator.Jwt)
	if err != nil {
		r.AddError("unable to decode operator jwt: %v", err.Error())
		return r, err
	}

	if p.rename != "" {
		r.AddOK("renaming operator %q to %q", oc.Name, p.rename)
		oc.Name = p.rename
	}

	theStore, err := GetConfig().LoadStore(p.operator.Name)
	if err == nil && theStore != nil && !p.force && p.rename == "" {
		r.AddError("operator %s already exist, '--force' to overwrite after creating a backup", p.operator.Name)
	}

	if theStore == nil {
		n := p.operator.Name
		if p.rename != "" {
			n = p.rename
		}
		nk := store.NamedKey{Name: n, KP: p.operator.Key.KeyPair}
		theStore, err = store.CreateStore(n, GetConfig().StoreRoot, &nk)
	}
	if theStore == nil {
		r.AddError("unable to create a store")
		return r, err
	}

	if err := theStore.StoreRaw([]byte(p.operator.Jwt)); err != nil {
		r.AddError("unable to store operator jwt: %v", err.Error())
		return r, err
	}

	r.AddOK("stored operator %s", oc.Name)
	kr := store.NewReport(store.OK, "Keys")
	r.Add(kr)

	// make a map of all the keys in the export
	keys := make(map[string]nkeys.KeyPair)
	keys[oc.Subject] = p.operator.Key.KeyPair
	for _, k := range p.operator.SigningKeys {
		keys[k.Key] = k.KeyPair
	}
	// and all the operator keys
	var pks []string
	pks = append(pks, oc.Subject)
	pks = append(pks, oc.SigningKeys...)
	for _, k := range pks {
		kp, ok := keys[k]
		if !ok || kp == nil {
			kr.AddWarning("%s was not exported", k)
		} else {
			if _, err := ctx.StoreCtx().KeyStore.Store(kp); err != nil {
				kr.AddError("unable to store %q: %v", k, err)
			} else {
				kr.AddOK("stored %q", k)
			}
		}
	}

	if len(p.operator.Accounts) == 0 {
		r.AddOK("no accounts exported")
		return r, nil
	}

	for _, a := range p.operator.Accounts {
		ar := store.NewReport(store.OK, "Account %s", a.Name)
		r.Add(ar)

		ac, err := jwt.DecodeAccountClaims(a.Jwt)
		if err != nil {
			ar.AddError("unable to decode account jwt: %v", err.Error())
			continue
		}

		if err := theStore.StoreRaw([]byte(a.Jwt)); err != nil {
			ar.AddError("unable to store account %q: %v", a.Name, err.Error())
			continue
		}
		ar.AddOK("imported account %q", a.Name)

		keys = make(map[string]nkeys.KeyPair)
		keys[ac.Subject] = a.Key.KeyPair
		for _, k := range a.SigningKeys {
			keys[k.Key] = k.KeyPair
		}
		pks = nil
		pks = append(pks, ac.Subject)
		for k := range ac.SigningKeys {
			pks = append(pks, k)
		}

		kr = store.NewReport(store.OK, "Keys")
		ar.Add(kr)
		for _, k := range pks {
			kp, ok := keys[k]
			if !ok || kp == nil {
				kr.AddWarning("%s was not exported", k)
			} else {
				if _, err := ctx.StoreCtx().KeyStore.Store(kp); err != nil {
					kr.AddError("unable to store %q: %v", k, err)
				} else {
					kr.AddOK("stored %q", k)
				}
			}
		}

		if len(a.Users) == 0 {
			ar.AddOK("no users exported")
			continue
		}

		for _, u := range a.Users {
			ur := store.NewReport(store.OK, "User %s", u.Name)
			ar.Add(ur)

			uc, err := jwt.DecodeUserClaims(u.Jwt)
			if err != nil {
				ur.AddError("unable to decode user jwt: %v", err.Error())
				continue
			}

			if err := theStore.StoreRaw([]byte(u.Jwt)); err != nil {
				ur.AddError("unable to store user %q: %v", u.Name, err.Error())
				continue
			}

			ur.AddOK("imported user %q", u.Name)
			if u.Key.KeyPair == nil {
				ar.AddWarning("key not exported")
			} else {
				if _, err := ctx.StoreCtx().KeyStore.Store(u.Key.KeyPair); err != nil {
					kr.AddError("unable to store %q: %v", uc.Subject, err)
				} else {
					kr.AddOK("stored %q", uc.Subject)
				}
			}
		}
	}
	if err := GetConfig().SetOperator(p.operator.Name); err != nil {
		return r, err
	}
	if err := GetConfig().Save(); err != nil {
		return r, err
	}

	return r, nil
}
