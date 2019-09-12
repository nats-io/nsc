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
)

type KeyCollectorParams struct {
	Operator     bool
	Accounts     bool
	Users        bool
	All          bool
	Unreferenced bool
	Account      string
	User         string
	Filter       string
}

func (p *KeyCollectorParams) SetDefaults(ctx ActionCtx) error {
	conf := GetConfig()

	if ctx.NothingToDo("operator", "accounts", "users", "all") {
		// default if no args
		account := p.Account
		if account == "" {
			account = conf.Account
		}
		p.Operator = true
		p.Account = account
		p.Accounts = true
		p.Users = true
	}
	if p.All {
		p.Operator = true
		p.Accounts = true
		p.Users = true
	}
	return nil
}

func (p *KeyCollectorParams) handleOperator(ctx ActionCtx) (KeyList, error) {
	var keys KeyList
	sctx := ctx.StoreCtx()

	// if we don't have a store - ignore this operator details
	if sctx.Operator.Name == "" {
		return nil, nil
	}
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

func (p *KeyCollectorParams) handleAccount(ctx ActionCtx, parent string, name string) (KeyList, error) {
	s := ctx.StoreCtx().Store
	ks := ctx.StoreCtx().KeyStore

	var keys KeyList

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
	return keys, nil
}

func (p *KeyCollectorParams) handleUsers(ctx ActionCtx, account string) (KeyList, error) {
	var keys KeyList

	s := ctx.StoreCtx().Store
	ac, err := s.ReadAccountClaim(account)
	if err != nil {
		return nil, err
	}

	users, err := s.ListEntries(store.Accounts, account, store.Users)
	if err != nil {
		return nil, err
	}
	sort.Strings(users)
	for _, u := range users {
		uk, err := p.handleUser(ctx, account, u)
		if err != nil {
			return nil, err
		}
		uk.Parent = ac.Subject
		keys = append(keys, uk)
	}
	return keys, nil
}

func (p *KeyCollectorParams) handleUser(ctx ActionCtx, account string, name string) (*Key, error) {
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

func (p *KeyCollectorParams) Run(ctx ActionCtx) (KeyList, error) {
	keys, err := p.handleOperator(ctx)
	if err != nil {
		return nil, err
	}

	// if we have an operator, we can resolve other things
	if keys != nil {
		var accounts []string
		if p.Account != "" {
			accounts = append(accounts, p.Account)
		} else {
			an, err := GetConfig().ListAccounts()
			if err != nil {
				return nil, err
			}
			accounts = append(accounts, an...)
		}
		for _, a := range accounts {
			akeys, err := p.handleAccount(ctx, keys[0].Pub, a)
			if err != nil {
				return nil, err
			}
			keys = append(keys, akeys...)

			if p.User != "" {
				uk, err := p.handleUser(ctx, a, p.User)
				if err != nil {
					return nil, err
				}
				keys = append(keys, uk)
			} else {
				ukeys, err := p.handleUsers(ctx, a)
				if err != nil {
					return nil, err
				}
				keys = append(keys, ukeys...)
			}
		}
	}

	if p.Unreferenced {
		all, err := ctx.StoreCtx().KeyStore.AllKeys()
		if err != nil {
			return nil, err
		}
		m := make(map[string]*Key)
		for _, v := range keys {
			m[v.Pub] = v
		}
		ks := ctx.StoreCtx().KeyStore
		var okeys KeyList
		var akeys KeyList
		var ukeys KeyList
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
		keys = KeyList{}
		keys = append(keys, okeys...)
		keys = append(keys, akeys...)
		keys = append(keys, ukeys...)
	}

	var keyFilter = strings.ToUpper(p.Filter)
	var filteredKeys KeyList
	for _, k := range keys {
		if !p.Operator && k.ExpectedKind == nkeys.PrefixByteOperator {
			continue
		}
		if !p.Accounts && k.ExpectedKind == nkeys.PrefixByteAccount {
			continue
		}
		if !p.Users && k.ExpectedKind == nkeys.PrefixByteUser {
			continue
		}
		if keyFilter != "" && !strings.Contains(k.Pub, keyFilter) {
			continue
		}
		filteredKeys = append(filteredKeys, k)
	}

	return filteredKeys, nil
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

type Keys struct {
	KeyList
	MessageFn func(ks Keys) string
}

func (keys Keys) Message() string {
	return keys.MessageFn(keys)
}

type KeyList []*Key

func (ks KeyList) Code() store.StatusCode {
	return store.OK
}

func (ks KeyList) Len() int {
	return len(ks)
}

func (ks KeyList) Swap(i, j int) {
	ks[i], ks[j] = ks[j], ks[i]
}

func (ks KeyList) Less(i, j int) bool {
	return ks[i].Pub < ks[j].Pub
}
