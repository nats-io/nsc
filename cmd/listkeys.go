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

	return cmd
}

func init() {
	listCmd.AddCommand(createListKeysCmd())
}

type ListKeysParams struct {
	operator bool
	accounts bool
	users    bool
	like     string
	all      bool
	Keys     Keys
}

type Key struct {
	Name    string
	Signing bool
	Pub     string
	KeyPath string
	Kind    nkeys.PrefixByte
	Invalid bool
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

func (ki Keys) Message() string {
	table := tablewriter.CreateTable()
	table.UTF8Box()

	table.AddTitle("Keys")
	table.AddHeaders("Entry", "Key", "Signing Key", "Stored")
	for _, k := range ki {
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
	return string(table.Render())
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

func (p *ListKeysParams) handleOperator(ctx ActionCtx) error {
	if p.operator {
		sctx := ctx.StoreCtx()
		oc, err := sctx.Store.ReadOperatorClaim()
		if err != nil {
			return err
		}
		var oki Key
		oki.Name = oc.Name
		oki.Kind = nkeys.PrefixByteOperator
		oki.Pub = oc.Subject
		oki.Resolve(sctx.KeyStore)
		p.Keys = append(p.Keys, &oki)

		for _, k := range oc.SigningKeys {
			var sk Key
			sk.Name = oc.Name
			sk.Pub = k
			sk.Signing = true
			sk.Kind = nkeys.PrefixByteOperator
			sk.Resolve(sctx.KeyStore)
			p.Keys = append(p.Keys, &sk)
		}

	}
	return nil
}

func (p *ListKeysParams) handleAccount(ctx ActionCtx, name string) error {
	s := ctx.StoreCtx().Store
	ks := ctx.StoreCtx().KeyStore

	if p.accounts {
		ac, err := s.ReadAccountClaim(name)
		if err != nil {
			return err
		}
		var aki Key
		aki.Name = ac.Name
		aki.Kind = nkeys.PrefixByteAccount
		aki.Pub = ac.Subject
		aki.Resolve(ks)
		p.Keys = append(p.Keys, &aki)

		for _, k := range ac.SigningKeys {
			var ask Key
			ask.Name = ac.Name
			ask.Pub = k
			ask.Signing = true
			ask.Resolve(ks)
			p.Keys = append(p.Keys, &ask)
		}

	}
	var users []string
	var err error
	if p.users {
		users, err = s.ListEntries(store.Accounts, config.Account, store.Users)
		if err != nil {
			return err
		}
		sort.Strings(users)

		for _, u := range users {
			if err := p.handleUser(ctx, name, u); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *ListKeysParams) handleUser(ctx ActionCtx, account string, name string) error {
	s := ctx.StoreCtx().Store
	ks := ctx.StoreCtx().KeyStore

	uc, err := s.ReadUserClaim(account, name)
	if err != nil {
		return err
	}
	var uki Key
	uki.Name = uc.Name
	uki.Pub = uc.Subject
	uki.Kind = nkeys.PrefixByteUser
	uki.Resolve(ks)
	p.Keys = append(p.Keys, &uki)
	return nil
}

func (p *ListKeysParams) PostInteractive(ctx ActionCtx) error {
	return nil
}

func (p *ListKeysParams) Validate(ctx ActionCtx) error {
	return nil
}

func (p *ListKeysParams) Run(ctx ActionCtx) (store.Status, error) {
	if err := p.handleOperator(ctx); err != nil {
		return nil, err
	}
	var accounts []string
	an, err := GetConfig().ListAccounts()
	if err != nil {
		return nil, err
	}
	accounts = append(accounts, an...)

	for _, a := range accounts {
		err := p.handleAccount(ctx, a)
		if err != nil {
			return nil, err
		}
	}

	var filteredKeys Keys
	if p.like != "" {
		p.like = strings.ToUpper(p.like)
		for _, k := range p.Keys {
			if strings.Contains(k.Pub, p.like) {
				filteredKeys = append(filteredKeys, k)
			}
		}
		p.Keys = filteredKeys
	}

	return p.Keys, nil
}
