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

	"github.com/nats-io/nsc/cli"
)

type NumberEditor struct {
	flagValue *int64
}

func NewNumberEditor(v *int64) *NumberEditor {
	return &NumberEditor{flagValue: v}
}

func (e *NumberEditor) Valid() error {
	// flag already insures this is a number
	return nil
}

func (e *NumberEditor) Edit(prompt string) error {
	var err error
	var nv int64
	sv := fmt.Sprintf("%d", *e.flagValue)
	sv, err = cli.Prompt(prompt, sv, true, func(s string) error {
		nv, err = ParseDataSize(s)
		return err
	})
	if err != nil {
		return err
	}
	*e.flagValue = nv
	return nil
}
