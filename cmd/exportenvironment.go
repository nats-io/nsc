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
	"path/filepath"
	"strings"

	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
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
	cmd.Flags().StringVarP(&params.out, "out", "o", "--", "output file, '--' is stdout")
	cmd.Flags().StringVarP(&params.name, "name", "n", "", "operator name")
	return cmd
}

func init() {
	exportCmd.AddCommand(createExportEnvironmentCmd())
}

type Environment struct {
	Operators []*Operator `json:"operators"`
}

type Base struct {
	Name        string      `json:"name"`
	Key         EntityKey   `json:"key,omitempty"`
	Jwt         string      `json:"token,omitempty"`
	SigningKeys []EntityKey `json:"signingKeys,omitempty"`
}

type Operator struct {
	Base
	Accounts []*Account `json:"accounts,omitempty"`
}

type Account struct {
	Base
	Users []*User `json:"users,omitempty"`
}

type User struct {
	Base
}

type EntityKey struct {
	Key     string
	Seed    string
	KeyPair nkeys.KeyPair
}

func (e *EntityKey) MarshalJSON() ([]byte, error) {
	if e.Seed != "" {
		return json.Marshal(e.Seed)
	}
	if e.KeyPair != nil {
		s, err := e.KeyPair.Seed()
		if err != nil {
			return nil, err
		}
		return json.Marshal(string(s))
	}
	return json.Marshal("")
}

func (e *EntityKey) UnmarshalJSON(data []byte) error {
	k := string(data)
	k = strings.Trim(k, "\"")

	// this is a string!
	if strings.HasPrefix(k, "S") {
		e.Seed = k
		kp, err := nkeys.FromSeed([]byte(k))
		if err != nil {
			return err
		}
		e.KeyPair = kp
		pk, err := kp.PublicKey()
		if err != nil {
			return err
		}
		e.Key = pk
	}
	return nil
}

func (e *EntityKey) GetKeyPair() nkeys.KeyPair {
	if e.Seed != "" {
		kp, err := nkeys.FromSeed([]byte(e.Seed))
		if err != nil {
			return nil
		}
		return kp
	}
	return nil
}

func (e *EntityKey) Reissue() error {
	var pk string
	var err error
	kp := e.GetKeyPair()
	if kp != nil {
		pk, err = kp.PublicKey()
		if err != nil {
			return err
		}
		e.Key = pk
	}
	var prefix nkeys.PrefixByte = 0
	switch e.Key[0] {
	case 'O':
		prefix = nkeys.PrefixByteOperator
	case 'A':
		prefix = nkeys.PrefixByteAccount
	case 'U':
		prefix = nkeys.PrefixByteUser
	case 'X':
		prefix = nkeys.PrefixByteCurve
	}
	if prefix == 0 {
		return fmt.Errorf("invalid key prefix: %v", e.Key[0])
	}
	kp, err = nkeys.CreatePair(prefix)
	if err != nil {
		return err
	}
	e.KeyPair = kp
	return nil
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
		fp := filepath.Join(current.StoreRoot, p.name)
		sto, err := store.LoadStore(fp)
		if err != nil {
			return err
		}
		ctx.StoreCtx().Store = sto
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

func ExportEnvironment(ctx ActionCtx, outFile string) (store.Status, error) {
	r := store.NewDetailedReport(false)
	s := ctx.StoreCtx().Store
	ks := ctx.StoreCtx().KeyStore

	token, err := s.ReadRawOperatorClaim()
	if err != nil {
		return nil, err
	}

	oc, err := s.ReadOperatorClaim()
	if err != nil {
		return nil, err
	}
	r.Add(store.NewReport(store.OK, "Operator %s (%s)", s.Info.Name, oc.Subject))
	kr := store.NewReport(store.OK, "Keys")
	r.Add(kr)

	var env Environment

	var operator Operator
	env.Operators = append(env.Operators, &operator)

	operator.Name = s.Info.Name
	operator.Jwt = string(token)
	oKeys, err := ctx.StoreCtx().GetOperatorKeys()
	if err != nil {
		return nil, err
	}
	for idx, k := range oKeys {
		kp, err := ks.GetKeyPair(k)
		if err != nil {
			kr.AddWarning("unable to read operator key %s: %v", k, err.Error())
			continue
		}
		if kp == nil {
			kr.AddWarning("unable operator key %s not found", k)
			continue
		}
		if idx == 0 {
			operator.Key = EntityKey{KeyPair: kp}
			kr.AddOK("exported operator key")
		} else {
			operator.SigningKeys = append(operator.SigningKeys, EntityKey{KeyPair: kp})
			kr.AddOK("exported operator signing key %s", k)
		}
	}

	accounts, err := ctx.StoreCtx().Store.ListSubContainers(store.Accounts)
	if err != nil {
		r.AddError("error listing accounts: %v", err.Error())
		return r, err
	}
	if len(accounts) == 0 {
		r.AddOK("no accounts found")
	}

	for _, a := range accounts {
		ac, err := s.ReadAccountClaim(a)
		if err != nil {
			r.AddError("error reading account %s: %v", a, err.Error())
		}

		ar := store.NewReport(store.OK, "%s (%s)", a, ac.Subject)
		r.Add(ar)
		if err != nil {
			ar.AddError("error reading account %s: %v", a, err.Error())
			continue
		}

		var account Account
		account.Name = a
		operator.Accounts = append(operator.Accounts, &account)

		ad, err := s.ReadRawAccountClaim(a)
		if err != nil {
			ar.AddError("error reading account %s: %v", a, err.Error())
			continue
		}
		account.Jwt = string(ad)

		var akeys []string
		akeys = append(akeys, ac.Subject)
		akeys = append(akeys, ac.SigningKeys.Keys()...)

		ak := store.NewReport(store.OK, "Keys")
		ar.Add(ak)
		for idx, k := range akeys {
			kp, err := ks.GetKeyPair(k)
			if err != nil {
				ak.AddWarning("unable to load account key %s: %v", k, err.Error())
				continue
			}
			if kp == nil {
				ak.AddWarning("account key %s not found", k)
				continue
			}
			if idx == 0 {
				account.Key = EntityKey{KeyPair: kp}
				ak.AddOK("exported account key")
			} else {
				account.SigningKeys = append(account.SigningKeys, EntityKey{KeyPair: kp})
				ak.AddOK("exported account signing key %s", k)
			}
		}

		users, err := s.ListEntries(store.Accounts, a, store.Users)
		if err != nil {
			r.AddError("error listing users for account %s: %v", a, err.Error())
			continue
		}

		if len(users) == 0 {
			r.Add(store.NewReport(store.OK, "No users found"))
		}

		for _, u := range users {
			uc, err := s.ReadUserClaim(a, u)
			if err != nil {
				ar.AddError("error reading user %s: %v", u, err.Error())
				continue
			}
			ur := store.NewReport(store.OK, "User %s (%s)", u, uc.Subject)
			ar.Add(ur)
			var user User
			user.Name = u
			account.Users = append(account.Users, &user)

			ud, err := s.ReadRawUserClaim(a, u)
			if err != nil {
				ur.AddError("error reading user %s: %v", u, err.Error())
				continue
			}
			user.Jwt = string(ud)

			ukp, err := ks.GetKeyPair(uc.Subject)
			if err != nil {
				ur.AddWarning("unable to read account %q user %q key %s: %v", a, u, uc.Subject, err.Error())
				continue
			}
			user.Key = EntityKey{KeyPair: ukp}
			ur.AddOK("exported user key")
		}
	}

	d, err := json.MarshalIndent(env, "", " ")
	if err != nil {
		r.AddError("error marshalling json: %v", err.Error())
		return r, err
	}

	if outFile == "--" {
		_, _ = fmt.Fprintln(ctx.CurrentCmd().OutOrStdout(), string(d))
	} else {
		err = WriteFile(outFile, d)
		if err != nil {
			r.AddError("error writing file: %v", err.Error())
			return r, err
		}
	}

	return r, nil
}

func (p *ExportEnvironmentParams) Run(ctx ActionCtx) (store.Status, error) {
	return ExportEnvironment(ctx, p.out)
}
