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
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
	"os"
)

func createExportEnvironmentCmd() *cobra.Command {
	var params ExportEnvironmentParams
	cmd := &cobra.Command{
		Use:          "environment",
		Short:        "export the environment for an operator including related accounts, users and keys",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunAction(cmd, args, &params)
		},
	}
	cmd.Flags().StringVarP(&params.out, "output-file", "o", "--", "output file, '--' is stdout")
	cmd.Flags().StringVarP(&params.name, "name", "n", "", "operator name")
	return cmd
}

func init() {
	exportCmd.AddCommand(createExportEnvironmentCmd())
}

type Entity struct {
	Name     string       `json:"name"`
	Jwt      string       `json:"jwt"`
	Keys     []*EntityKey `json:"keys,omitempty"`
	Children []*Entity    `json:"children,omitempty"`
}

type EntityKey struct {
	Key     string
	Seed    string
	KeyPair nkeys.KeyPair
}

func (e *EntityKey) GetKeyPair() nkeys.KeyPair {
	if e.Seed != "" {
		kp, err := nkeys.FromSeed([]byte(e.Seed))
		if err != nil {
			return nil
		}
		e.KeyPair = kp
		return kp
	}
	return nil
}

func (e *EntityKey) MarshalJSON() ([]byte, error) {
	type E struct {
		Key  string `json:"key,omitempty"`
		Seed string `json:"seed,omitempty"`
	}

	rc := E{}
	if e.Seed != "" {
		kp, err := nkeys.FromSeed([]byte(e.Seed))
		if err != nil {
			return nil, err
		}
		rc.Seed = e.Seed
		pk, err := kp.PublicKey()
		if err != nil {
			rc.Key = pk
		}
	} else {
		rc.Key = e.Key
	}
	return json.Marshal(rc)
}

type ExportEnvironmentParams struct {
	name string
	out  string
}

func (p *ExportEnvironmentParams) SetDefaults(ctx ActionCtx) error {
	p.name = NameFlagOrArgument(p.name, ctx)
	if p.name == "" {
		p.name = ctx.StoreCtx().Operator.Name
	}
	if p.name != ctx.StoreCtx().Operator.Name {
		current := GetConfig()
		if err := current.SetOperator(p.name); err != nil {
			return err
		}
		if err := current.Save(); err != nil {
			return err
		}
	}
	return nil
}

func (p *ExportEnvironmentParams) PreInteractive(ctx ActionCtx) error {
	return nil
}

func (p *ExportEnvironmentParams) Load(ctx ActionCtx) error {
	return nil
}

func (p *ExportEnvironmentParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *ExportEnvironmentParams) Validate(ctx ActionCtx) error {
	return nil
}

func (p *ExportEnvironmentParams) Run(ctx ActionCtx) (store.Status, error) {
	r := store.NewDetailedReport(true)
	s := ctx.StoreCtx().Store
	ks := ctx.StoreCtx().KeyStore

	token, err := s.ReadRawOperatorClaim()
	if err != nil {
		return nil, err
	}

	root := &Entity{Name: ctx.StoreCtx().Operator.Name, Jwt: string(token)}
	oKeys, err := ctx.StoreCtx().GetOperatorKeys()
	if err != nil {
		return nil, err
	}
	for _, k := range oKeys {
		kp, err := ks.GetKeyPair(k)
		if err != nil {
			r.AddWarning("unable to read operator key %s: %v", k, err.Error())
			root.Keys = append(root.Keys, &EntityKey{Key: k})
			continue
		}
		seed, err := kp.Seed()
		if err != nil {
			r.AddWarning("failed reading seed for %s: %v", k, err.Error())
			root.Keys = append(root.Keys, &EntityKey{Key: k})
			continue
		}
		root.Keys = append(root.Keys, &EntityKey{Seed: string(seed), Key: k})
	}

	accounts, err := config.ListAccounts()
	if err != nil {
		r.AddError("error listing accounts: %v", err.Error())
		return r, err
	}

	for _, a := range accounts {
		account := &Entity{Name: a}
		root.Children = append(root.Children, account)

		ad, err := s.ReadRawAccountClaim(a)
		if err != nil {
			r.AddError("error reading account %s: %v", a, err.Error())
			continue
		}
		account.Jwt = string(ad)
		ac, err := s.ReadAccountClaim(a)
		if err != nil {
			r.AddError("error reading account %s: %v", a, err.Error())
			continue
		}
		var akeys []string
		akeys = append(akeys, ac.Subject)
		for _, sk := range ac.SigningKeys.Keys() {
			akeys = append(akeys, sk)
		}
		for _, k := range akeys {
			kp, err := ks.GetKeyPair(k)
			if err != nil {
				r.AddWarning("unable to read account key %s: %v", k, err.Error())
				account.Keys = append(account.Keys, &EntityKey{Key: k})
				continue
			}
			seed, err := kp.Seed()
			if err != nil {
				r.AddWarning("failed reading seed for %s: %v", k, err.Error())
				account.Keys = append(account.Keys, &EntityKey{Key: k})
				continue
			}
			account.Keys = append(account.Keys, &EntityKey{Seed: string(seed), Key: k})
		}

		users, err := s.ListEntries(store.Accounts, a, store.Users)
		if err != nil {
			r.AddError("error listing users for account %s: %v", a, err.Error())
			continue
		}

		for _, u := range users {
			user := &Entity{Name: u}
			account.Children = append(account.Children, user)

			ud, err := s.ReadRawUserClaim(a, u)
			if err != nil {
				r.AddError("error reading user %s: %v", u, err.Error())
				continue
			}
			user.Jwt = string(ud)
			uc, err := s.ReadUserClaim(a, u)
			if err != nil {
				r.AddError("error reading user %s: %v", u, err.Error())
				continue
			}
			ukp, err := ks.GetKeyPair(uc.Subject)
			if err != nil {
				r.AddWarning("unable to read account %q user %q key %s: %v", a, u, uc.Subject, err.Error())
				user.Keys = append(user.Keys, &EntityKey{Key: uc.Subject})
				continue
			}
			seed, err := ukp.Seed()
			if err != nil {
				r.AddError("unable to read account %q user %q key %s: %v", a, u, uc.Subject, err.Error())
				user.Keys = append(user.Keys, &EntityKey{Key: uc.Subject})
				continue
			}
			user.Keys = append(user.Keys, &EntityKey{Seed: string(seed), Key: uc.Subject})
		}
	}

	d, err := json.MarshalIndent(root, "", " ")
	if err != nil {
		r.AddError("error marshalling json: %v", err.Error())
		return r, err
	}

	if p.out == "--" {
		_, _ = fmt.Fprintln(ctx.CurrentCmd().OutOrStdout(), string(d))
	} else {
		err = WriteFile(p.out, d)
		if err != nil {
			r.AddError("error writing file: %v", err.Error())
			return r, err
		}
	}

	return nil, nil
}

type ImportEnvironmentParams struct {
	in     string
	force  bool
	entity Entity
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
	cmd.Flags().BoolVarP(&params.force, "force", "", false, "overwrite existing operator")
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
	if err := json.Unmarshal(data, &p.entity); err != nil {
		return err
	}
	if p.entity.Name == "" || p.entity.Jwt == "" {
		return fmt.Errorf("invalid input file, operator name/jwt required")
	}
	operators := config.ListOperators()
	found := false
	for _, o := range operators {
		if o == p.entity.Name {
			found = true
			break
		}
	}
	if found && !p.force {
		return fmt.Errorf("operator %s already exist, '--force' to overwrite after creating a backup", p.entity.Name)
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
	op := store.NewDetailedReport(false)

	oc, err := jwt.DecodeOperatorClaims(p.entity.Jwt)
	if err != nil {
		op.AddError("unable to decode operator jwt: %v", err.Error())
		return op, err
	}

	var okp nkeys.KeyPair

	for _, k := range p.entity.Keys {
		kp := k.GetKeyPair()
		if k.Key == oc.Subject {
			okp = kp
		}
	}

	if okp == nil {
		op.AddError("unable to find operator key")
		return op, nil
	}

	theStore, err := GetConfig().LoadStore(p.entity.Name)
	if err == nil && theStore != nil && !p.force {
		op.AddError("operator %s already exist, '--force' to overwrite after creating a backup", p.entity.Name)
	}
	if theStore == nil {
		nk := store.NamedKey{Name: p.entity.Name, KP: okp}
		theStore, err = store.CreateStore(p.entity.Name, GetConfig().StoreRoot, &nk)
	}
	if theStore == nil {
		op.AddError("unable to create a store")
		return op, err
	}
	if err := theStore.StoreRaw([]byte(p.entity.Jwt)); err != nil {
		op.AddError("unable to store operator jwt: %v", err.Error())
		return op, err
	}

	op.AddOK("imported operator %q", p.entity.Name)

	for idx, k := range p.entity.Keys {
		kp := k.GetKeyPair()
		if kp != nil {
			op.AddError("unable to store operator key %q: %v", p.entity.Keys[idx], err)
		}
		if _, err := ctx.StoreCtx().KeyStore.Store(kp); err != nil {
			op.AddError("unable to store operator key %q: %v", p.entity.Keys[idx], err)
		}
		op.AddOK(" imported key %s", k.Seed)
	}

	for _, a := range p.entity.Children {
		ra := store.NewDetailedReport(false)
		op.Add(ra)

		if err := theStore.StoreRaw([]byte(a.Jwt)); err != nil {
			ra.AddError("unable to store account %q: %v", a.Name, err.Error())
			continue
		}
		ra.AddOK("imported account %q", a.Name)

		for _, k := range a.Keys {
			kp := k.GetKeyPair()
			if kp == nil {
				ra.AddError("account key %q not available", k.Key)
			}
			if _, err := ctx.StoreCtx().KeyStore.Store(kp); err != nil {
				ra.AddError("unable to store key %q: %v", k, err)
				continue
			}
			ra.AddOK("imported key %q", k.Seed)
		}

		for _, u := range a.Children {
			ru := store.NewDetailedReport(false)
			ra.Add(ru)
			if err := theStore.StoreRaw([]byte(u.Jwt)); err != nil {
				ru.AddError("unable to store user %q: %v", u.Name, err.Error())
				continue
			}
			ru.AddOK("imported user %q", u.Name)

			for _, k := range u.Keys {
				kp := k.GetKeyPair()
				if kp == nil {
					ru.AddError("user key not available %q", k)
					continue
				}
				if _, err := ctx.StoreCtx().KeyStore.Store(kp); err != nil {
					ru.AddError("unable store key %q: %v", k, err)
					continue
				}
				ru.AddOK("imported key %q", k.Seed)
			}
		}

	}

	return op, nil
}
