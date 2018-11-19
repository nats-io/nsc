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

	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cli"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/spf13/cobra"
)

type NKeyParams struct {
	flagName string
	private  bool
	path     string
	kind     nkeys.PrefixByte
	kp       nkeys.KeyPair
}

func (e *NKeyParams) BindFlags(flagName string, kind nkeys.PrefixByte, seed bool, cmd *cobra.Command) {
	e.flagName = flagName
	e.kind = kind
	e.private = seed
	cmd.Flags().StringVarP(&e.path, flagName, "", "", fmt.Sprintf("%s keypath", flagName))
}

func (e *NKeyParams) valid(s string) error {
	if s == "" {
		return fmt.Errorf("%s nkey cannot be empty", store.KeyTypeLabel(e.kind))
	}
	kp, err := store.ResolveKey(s)
	if err != nil {
		return err
	}
	if !store.KeyPairTypeOk(e.kind, kp) {
		return fmt.Errorf("invalid %s nkey", store.KeyTypeLabel(e.kind))
	}
	if e.private {
		_, err = kp.Seed()
		if err != nil {
			return fmt.Errorf("%s nkey is not a seed", store.KeyTypeLabel(e.kind))
		}
	}
	e.kp = kp

	return nil
}

func (e *NKeyParams) Valid() error {
	return e.valid(e.path)
}

func (e *NKeyParams) KeyPair() (nkeys.KeyPair, error) {
	if e.kp != nil {
		return e.kp, nil
	}
	if err := e.Valid(); err != nil {
		return nil, err
	}
	return e.kp, nil
}

func (e *NKeyParams) PublicKey() (string, error) {
	kp, err := e.KeyPair()
	if err != nil {
		return "", err
	}
	d, err := kp.PublicKey()
	if err != nil {
		return "", err
	}
	return string(d), nil
}

func (e *NKeyParams) Edit() error {
	sv, err := cli.Prompt(fmt.Sprintf("%s nkey", e.flagName), e.path, true, e.valid)
	if err != nil {
		return err
	}
	e.path = sv
	return nil
}
