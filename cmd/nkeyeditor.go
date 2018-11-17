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
	"github.com/nats-io/nsc/cmd/store"

	"github.com/nats-io/nsc/cli"
)

type NKeyEditor struct {
	strPtr *string
	kind   nkeys.PrefixByte
}

func NewNKeyEditor(v *string, kind nkeys.PrefixByte) *NKeyEditor {
	return &NKeyEditor{strPtr: v, kind: kind}
}

func (e *NKeyEditor) valid(s string) error {
	kp, err := store.ResolveKey(s)
	if err != nil {
		return err
	}
	if !store.KeyPairTypeOk(e.kind, kp) {
		return fmt.Errorf("invalid %s nkey", store.KeyTypeLabel(e.kind))
	}
	return nil
}

func (e *NKeyEditor) Valid() error {
	return e.valid(*e.strPtr)
}

func (e *NKeyEditor) Edit(prompt string) error {
	sv, err := cli.Prompt(prompt, *e.strPtr, true, e.valid)
	if err != nil {
		return err
	}
	*e.strPtr = sv
	return nil
}
