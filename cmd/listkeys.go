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
	"sort"
	"strings"

	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
	"github.com/xlab/tablewriter"
)

func createListKeysCmd() *cobra.Command {
	var params ListKeysParams
	cmd := &cobra.Command{
		Use:          "keys",
		Short:        "list keys related accounts and users in the current operator",
		Args:         MaxArgs(0),
		SilenceUsage: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := RunAction(cmd, args, &params); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&params.operator, "operator", "o", false, "show operator keys")
	cmd.Flags().BoolVarP(&params.accounts, "accounts", "a", false, "show account keys")
	cmd.Flags().BoolVarP(&params.users, "users", "u", false, "show user keys")
	cmd.Flags().BoolVarP(&params.all, "all", "A", false, "show operator, accounts and users")
	cmd.Flags().StringVarP(&params.like, "like", "", "", "filter keys containing string")
	cmd.Flags().BoolVarP(&params.unreferenced, "not-in-context", "", false, "shows keys that are not referenced in the current operator context")

	return cmd
}

func init() {
	listCmd.AddCommand(createListKeysCmd())
}

type ListKeysParams struct {
	operator     bool
	accounts     bool
	account      string
	users        bool
	user         string
	like         string
	all          bool
	unreferenced bool ``
}

type Key struct {
	Name         string
	Pub          string
	Parent       string
	ExpectedKind nkeys.PrefixByte
	Signing      bool
	KeyPath      string
	Invalid      bool
}

func (k *Key) Resolve(ks store.KeyStore) {
	kp, _ := ks.GetKeyPair(k.Pub)
	if kp != nil {
		k.KeyPath = ks.GetKeyPath(k.Pub)
		pk, _ := kp.PublicKey()
		k.Invalid = pk != k.Pub
	}
}

func (k *Key) HasKey() bool {
	return k.KeyPath != ""
}

type Keys []*Key

func (ki Keys) Len() int {
	return len(ki)
}

func (ki Keys) Swap(i, j int) {
	ki[i], ki[j] = ki[j], ki[i]
}

func (ki Keys) Less(i, j int) bool {
	return ki[i].Pub < ki[j].Pub
}

func (ki Keys) Message() string {
	if len(ki) == 0 {
		return "no keys matched query"
	}
	var hasUnreferenced bool
	table := tablewriter.CreateTable()
	table.UTF8Box()
	table.AddTitle("Keys")
	table.AddHeaders("Entity", "Key", "Signing Key", "Stored")
	for _, k := range ki {
		if k.Name == "?" {
			hasUnreferenced = true
		}
		sk := ""
		if k.Signing {
			sk = "*"
		}
		stored := ""
		if k.HasKey() {
			stored = "*"
		}
		if k.Invalid {
			stored = "BAD"
		}
		table.AddRow(k.Name, k.Pub, sk, stored)
	}
	s := table.Render()
	if hasUnreferenced {
		s = fmt.Sprintf("%s[?] unreferenced key - may belong to a different context", s)
	}
	return s
}

func (p *ListKeysParams) SetDefaults(ctx ActionCtx) error {
	if p.all {
		p.operator = true
		p.accounts = true
		p.users = true
	}
	return nil
}

func (p *ListKeysParams) PreInteractive(ctx ActionCtx) error {
	return nil
}

func (p *ListKeysParams) Load(ctx ActionCtx) error {
	return nil
}

func (p *ListKeysParams) handleOperator(ctx ActionCtx) (Keys, error) {
	var keys Keys
	sctx := ctx.StoreCtx()
	oc, err := sctx.Store.ReadOperatorClaim()
	if err != nil {
		return nil, err
	}
	var oki Key
	oki.Name = oc.Name
	oki.ExpectedKind = nkeys.PrefixByteOperator
	oki.Pub = oc.Subject
	oki.Resolve(sctx.KeyStore)
	keys = append(keys, &oki)

	for _, k := range oc.SigningKeys {
		var sk Key
		sk.Name = oc.Name
		sk.Pub = k
		sk.Signing = true
		sk.ExpectedKind = nkeys.PrefixByteOperator
		sk.Resolve(sctx.KeyStore)
		keys = append(keys, &sk)
	}

	return keys, nil
}

func (p *ListKeysParams) handleAccount(ctx ActionCtx, parent string, name string) (Keys, error) {
	s := ctx.StoreCtx().Store
	ks := ctx.StoreCtx().KeyStore

	var keys Keys

	ac, err := s.ReadAccountClaim(name)
	if err != nil {
		return nil, err
	}
	var aki Key
	aki.Parent = parent
	aki.Name = ac.Name
	aki.ExpectedKind = nkeys.PrefixByteAccount
	aki.Pub = ac.Subject
	aki.Resolve(ks)
	keys = append(keys, &aki)

	for _, k := range ac.SigningKeys {
		var ask Key
		ask.Name = ac.Name
		ask.Pub = k
		ask.Signing = true
		ask.Resolve(ks)
		keys = append(keys, &ask)
	}

	var users []string
	users, err = s.ListEntries(store.Accounts, name, store.Users)
	if err != nil {
		return nil, err
	}
	sort.Strings(users)
	for _, u := range users {
		uk, err := p.handleUser(ctx, name, u)
		if err != nil {
			return nil, err
		}
		uk.Parent = ac.Subject
		keys = append(keys, uk)
	}
	return keys, nil
}

func (p *ListKeysParams) handleUser(ctx ActionCtx, account string, name string) (*Key, error) {
	s := ctx.StoreCtx().Store
	ks := ctx.StoreCtx().KeyStore

	uc, err := s.ReadUserClaim(account, name)
	if err != nil {
		return nil, err
	}
	var uki Key
	uki.Name = uc.Name
	uki.Pub = uc.Subject
	uki.ExpectedKind = nkeys.PrefixByteUser
	uki.Resolve(ks)
	return &uki, nil
}

func (p *ListKeysParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *ListKeysParams) Validate(ctx ActionCtx) error {
	return nil
}

func (p *ListKeysParams) Run(ctx ActionCtx) (store.Status, error) {
	keys, err := p.handleOperator(ctx)
	if err != nil {
		return nil, err
	}

	var accounts []string
	an, err := GetConfig().ListAccounts()
	if err != nil {
		return nil, err
	}
	accounts = append(accounts, an...)

	for _, a := range accounts {
		akeys, err := p.handleAccount(ctx, keys[0].Pub, a)
		if err != nil {
			return nil, err
		}
		keys = append(keys, akeys...)
	}

	if p.unreferenced {
		all, err := ctx.StoreCtx().KeyStore.AllKeys()
		if err != nil {
			return nil, err
		}
		m := make(map[string]*Key)
		for _, v := range keys {
			m[v.Pub] = v
		}
		ks := ctx.StoreCtx().KeyStore
		var okeys Keys
		var akeys Keys
		var ukeys Keys
		for _, v := range all {
			_, ok := m[v]
			if !ok {
				var k Key
				k.Name = "?"
				k.Pub = v
				k.ExpectedKind, err = store.PubKeyType(k.Pub)
				if err != nil {
					return nil, err
				}
				k.Resolve(ks)
				switch k.ExpectedKind {
				case nkeys.PrefixByteOperator:
					okeys = append(okeys, &k)
				case nkeys.PrefixByteAccount:
					akeys = append(akeys, &k)
				case nkeys.PrefixByteUser:
					ukeys = append(ukeys, &k)
				}
			}
		}
		sort.Sort(okeys)
		sort.Sort(akeys)
		sort.Sort(ukeys)
		keys = append(keys, okeys...)
		keys = append(keys, akeys...)
		keys = append(keys, ukeys...)
	}

	var keyFilter = strings.ToUpper(p.like)
	var filteredKeys Keys
	for _, k := range keys {
		if !p.operator && k.ExpectedKind == nkeys.PrefixByteOperator {
			continue
		}
		if !p.accounts && k.ExpectedKind == nkeys.PrefixByteAccount {
			continue
		}
		if !p.users && k.ExpectedKind == nkeys.PrefixByteUser {
			continue
		}
		if keyFilter != "" && !strings.Contains(k.Pub, keyFilter) {
			continue
		}
		filteredKeys = append(filteredKeys, k)
	}

	return filteredKeys, nil
}
