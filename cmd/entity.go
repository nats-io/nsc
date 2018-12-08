/*
 * Copyright 2018 The NATS Authors
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

	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
	"github.com/nats-io/nsc/cmd/store"
)

type EntityClaimsEditor func(interface{}, ActionCtx) error

type Entity struct {
	create    bool
	dir       string
	generated bool
	keyPath   string
	kind      nkeys.PrefixByte
	kp        nkeys.KeyPair
	name      string
	editFn    EntityClaimsEditor
}

func (c *Entity) Valid() error {
	var err error
	if c.keyPath != "" {
		c.kp, err = store.ResolveKey(c.keyPath)
		if err != nil {
			return err
		}

		if !store.KeyPairTypeOk(c.kind, c.kp) {
			return fmt.Errorf("invalid %s key", c.kind.String())
		}

	} else {
		c.kp, err = nkeys.CreatePair(c.kind)
		if err != nil {
			return err
		}
		c.generated = true
	}

	s, _ := GetStore()
	if s == nil {
		// this happens on init
		return nil
	}

	ctx, err := s.GetContext()
	if err != nil {
		return err
	}

	exists := false
	switch c.kind {
	case nkeys.PrefixByteOperator:
		exists = s.Has(store.JwtName(c.name))
	case nkeys.PrefixByteAccount:
		exists = s.Has(store.Accounts, c.name, store.JwtName(c.name))
	case nkeys.PrefixByteUser:
		exists = s.Has(store.Accounts, ctx.Account.Name, store.Users, store.JwtName(c.name))
	case nkeys.PrefixByteCluster:
		exists = s.Has(store.Clusters, c.name, store.JwtName(c.name))
	case nkeys.PrefixByteServer:
		exists = s.Has(store.Clusters, ctx.Cluster.Name, store.Servers, store.JwtName(c.name))
	default:
		return fmt.Errorf("unexpected type of entity")
	}

	if exists {
		return fmt.Errorf("the %s %q already exists", c.kind.String(), c.name)
	}

	return nil
}

func (c *Entity) StoreKeys(parent string) error {
	if c.create && c.keyPath == "" {
		s, err := GetStore()
		if err != nil {
			return err
		}
		ctx, err := s.GetContext()
		if c.keyPath, err = ctx.KeyStore.Store(c.name, c.kp, parent); err != nil {
			return err
		}
	}
	return nil
}

func (c *Entity) KeySource() string {
	if c.keyPath == "" {
		return "Generated"
	}
	return c.keyPath
}

func (c *Entity) Edit() error {
	var err error
	label := c.kind.String()

	c.name, err = cli.Prompt(fmt.Sprintf("%s name", label), c.name, true, cli.LengthValidator(1))
	if err != nil {
		return err
	}

	ok, err := cli.PromptYN(fmt.Sprintf("generate an %s nkey", label))
	if err != nil {
		return err
	}
	if !ok {
		c.keyPath, err = cli.Prompt(fmt.Sprintf("path to the %s nkey", label), "", true, c.ValidateNKey())
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Entity) GenerateClaim(signer nkeys.KeyPair, ctx ActionCtx) error {
	if !c.create {
		return nil
	}
	// self-sign if we don't have a parent keypair
	if signer == nil {
		signer = c.kp
	}

	pub, err := c.kp.PublicKey()
	if err != nil {
		return err
	}

	s, err := GetStore()
	if err != nil {
		return err
	}

	var claim jwt.Claims
	switch c.kind {
	case nkeys.PrefixByteOperator:
		claim = jwt.NewOperatorClaims(pub)
	case nkeys.PrefixByteAccount:
		ac := jwt.NewAccountClaims(pub)
		if s.IsManaged() {
			ac.Limits = jwt.OperatorLimits{}
		}
		claim = ac
	case nkeys.PrefixByteUser:
		claim = jwt.NewUserClaims(pub)
	case nkeys.PrefixByteCluster:
		claim = jwt.NewClusterClaims(pub)
	case nkeys.PrefixByteServer:
		claim = jwt.NewServerClaims(pub)
	}
	d := claim.Claims()
	d.Name = c.name

	if c.editFn != nil {
		if err = c.editFn(claim, ctx); err != nil {
			return err
		}
	}

	token, err := claim.Encode(signer)
	if err != nil {
		return err
	}

	return s.StoreClaim([]byte(token))
}

func (c *Entity) ValidateNKey() cli.Validator {
	return func(v string) error {
		nk, err := store.ResolveKey(v)
		if err != nil {
			return err
		}
		t, err := store.KeyType(nk)
		if err != nil {
			return err
		}
		if t != c.kind {
			return fmt.Errorf("specified key is not valid for an %s", c.kind.String())
		}
		return nil
	}
}
