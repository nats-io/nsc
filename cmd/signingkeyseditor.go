/*
 *
 *  * Copyright 2018-2022 The NATS Authors
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package cmd

import (
	"fmt"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
)

type SigningKeysParams struct {
	flagName string
	paths    []string
	kind     nkeys.PrefixByte
}

func (e *SigningKeysParams) BindFlags(flagName string, shorthand string, kind nkeys.PrefixByte, cmd *cobra.Command) {
	e.flagName = flagName
	e.kind = kind
	if kind == nkeys.PrefixByteCurve {
		e.paths = make([]string, 1)
		cmd.Flags().StringVarP(&e.paths[0], flagName, shorthand, "", `curve key or keypath or the value "generate" to generate a curve encryption target key on the fly`)
	} else {
		cmd.Flags().StringSliceVarP(&e.paths, flagName, shorthand, nil, `signing key or keypath or the value "generate" to generate a key pair on the fly - comma separated list or option can be specified multiple times`)
	}
}

func (e *SigningKeysParams) BindFlagsForOne(flagName string, shorthand string, kind nkeys.PrefixByte, cmd *cobra.Command) {
	e.flagName = flagName
	e.kind = kind
	if kind == nkeys.PrefixByteCurve {
		e.paths = make([]string, 1)
		cmd.Flags().StringVarP(&e.paths[0], flagName, shorthand, "", `curve key or keypath or the value "generate" to generate a curve encryption target key on the fly`)
	} else {
		cmd.Flags().StringSliceVarP(&e.paths, flagName, shorthand, nil, `signing key or keypath or the value "generate" to generate a key pair on the fly`)
	}
}

func (e *SigningKeysParams) valid(s string) error {
	if s == "generate" {
		return nil
	}
	_, err := e.resolve(s)
	return err
}

func (e *SigningKeysParams) resolve(s string) (nkeys.KeyPair, error) {
	if s == "" {
		return nil, fmt.Errorf("signing key cannot be empty")
	}
	if s == "generate" {
		if kp, err := nkeys.CreatePair(e.kind); err != nil {
			return nil, err
		} else if s, err = kp.PublicKey(); err != nil {
			return nil, err
		} else if _, err = store.StoreKey(kp); err != nil {
			return nil, err
		}
	}
	kp, err := store.ResolveKey(s)
	if err != nil {
		return nil, err
	}

	if kp == nil {
		return nil, fmt.Errorf("a %s key is required", e.label())
	}
	if !store.KeyPairTypeOk(e.kind, kp) {
		return nil, fmt.Errorf("invalid %s %s key %q", e.kind.String(), e.label(), s)
	}

	return kp, nil
}

func (e *SigningKeysParams) label() string {
	label := "signing"
	if e.kind == nkeys.PrefixByteCurve {
		label = "curve"
	}
	return label
}

func (e *SigningKeysParams) Valid() error {
	for _, v := range e.paths {
		if err := e.valid(v); err != nil {
			return err
		}
	}
	return nil
}

func (e *SigningKeysParams) Empty() bool {
	return len(e.paths) == 0
}

func (e *SigningKeysParams) PublicKeys() ([]string, error) {
	var keys []string
	for _, v := range e.paths {
		kp, err := e.resolve(v)
		if err != nil {
			return nil, err
		}
		pk, err := kp.PublicKey()
		if err != nil {
			return nil, err
		}
		keys = append(keys, pk)
	}
	return keys, nil
}

func (e *SigningKeysParams) Edit() error {
	// verify any keys that were added via flags
	for i, v := range e.paths {
		sv, err := cli.Prompt(fmt.Sprintf("path to %s nkey or nkey", e.flagName), v, cli.Val(e.valid))
		if err != nil {
			return err
		}
		e.paths[i] = sv
	}
	first := true

	for {
		m := fmt.Sprintf("add a %s key", e.label())
		if !first || len(e.paths) > 0 {
			m = fmt.Sprintf("add another %s key", e.label())
		}
		first = false

		ok, err := cli.Confirm(m, false)
		if err != nil {
			return err
		}
		if !ok {
			break
		}
		sv, err := cli.Prompt(fmt.Sprintf("path to %s nkey or nkey", e.flagName), "", cli.Val(e.valid))
		if err != nil {
			return err
		}
		e.paths = append(e.paths, sv)
	}
	return nil
}
