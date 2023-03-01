/*
 * Copyright 2018-2022 The NATS Authors
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

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/nats-io/nsc/v2/cmd/store"

	"github.com/spf13/cobra"
)

type PubKeyChoice struct {
	Label string
	Key   string
}

type PubKeyParams struct {
	flagName      string
	kind          nkeys.PrefixByte
	publicKey     string
	AllowWildcard bool
}

func (e *PubKeyParams) SetDefaults(ctx ActionCtx) error {
	if e.publicKey == "" || e.publicKey == "*" || store.IsPublicKey(e.kind, e.publicKey) {
		return nil
	}
	switch e.kind {
	case nkeys.PrefixByteAccount:
		if c, err := ctx.StoreCtx().Store.ReadAccountClaim(e.publicKey); err != nil {
			return err
		} else {
			e.publicKey = c.Subject
		}
	case nkeys.PrefixByteUser:
		an := ctx.StoreCtx().Account.Name
		if c, err := ctx.StoreCtx().Store.ReadUserClaim(an, e.publicKey); err != nil {
			return err
		} else {
			e.publicKey = c.Subject
		}
	}
	return nil
}

func (e *PubKeyParams) BindFlags(flagName string, shorthand string, kind nkeys.PrefixByte, cmd *cobra.Command) {
	e.flagName = flagName
	e.kind = kind
	cmd.Flags().StringVarP(&e.publicKey, flagName, shorthand, "", flagName)
}

func (e *PubKeyParams) valid(s string) error {
	if s == "" {
		return fmt.Errorf("%s cannot be empty", e.flagName)
	}
	if e.AllowWildcard && s == jwt.All {
		return nil
	}

	if !store.IsPublicKey(e.kind, s) {
		return fmt.Errorf("%s is not a valid %q public key", e.publicKey, e.kind.String())
	}

	return nil
}

func (e *PubKeyParams) Valid() error {
	return e.valid(e.publicKey)
}

func (e *PubKeyParams) Select(label string, choices ...PubKeyChoice) error {
	var labels []string
	for _, c := range choices {
		labels = append(labels, c.Label)
	}
	sel, err := cli.Select(label, "", labels)
	if err != nil {
		return err
	}
	if sel == -1 {
		return fmt.Errorf("nothing selected")
	}
	e.publicKey = choices[sel].Key
	return nil
}

func (e *PubKeyParams) Edit() error {
	m := fmt.Sprintf("%s public key", e.flagName)
	if e.AllowWildcard {
		m = fmt.Sprintf("%s or '*' to match any %s", m, e.flagName)
	}
	sv, err := cli.Prompt(m, e.publicKey, cli.Val(e.valid))
	if err != nil {
		return err
	}
	e.publicKey = sv
	return nil
}
