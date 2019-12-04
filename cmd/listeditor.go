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

	cli "github.com/nats-io/cliprompts/v2"
)

type ListEditorParam struct {
	PromptMessage string
	AddMessage    string
	FlagName      string
	Values        []string
	ValidatorFn   cli.Validator
}

func (e *ListEditorParam) Valid() error {
	if e.ValidatorFn == nil {
		return nil
	}
	for _, v := range e.Values {
		if err := e.ValidatorFn(v); err != nil {
			return err
		}
	}
	return nil
}

func (e *ListEditorParam) GetValues() []string {
	return e.Values
}

func (e *ListEditorParam) Edit() error {
	if e.PromptMessage == "" {
		e.PromptMessage = fmt.Sprintf("edit %s", e.FlagName)
	}
	if e.AddMessage == "" {
		e.AddMessage = fmt.Sprintf("add %s", e.FlagName)
	}
	for i, v := range e.Values {
		sv, err := cli.Prompt(e.PromptMessage, v, cli.Val(e.ValidatorFn))
		if err != nil {
			return err
		}
		e.Values[i] = sv
	}
	for {
		ok, err := cli.Confirm(e.AddMessage, true)
		if err != nil {
			return err
		}
		if !ok {
			break
		}
		sv, err := cli.Prompt(e.PromptMessage, "", cli.Val(e.ValidatorFn))
		if err != nil {
			return err
		}
		e.Values = append(e.Values, sv)
	}
	return nil
}
