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
	cli "github.com/nats-io/cliprompts/v2"
)

type DataParams struct {
	Value  string
	Number int64
}

func (e *DataParams) Valid() error {
	// flag already insures this is a number
	return nil
}

func (e *DataParams) Edit(prompt string) error {
	var err error
	var nv int64
	sv, err := cli.Prompt(prompt, e.Value, cli.Val(func(s string) error {
		nv, err = ParseNumber(s)
		return err
	}))
	if err != nil {
		return err
	}
	e.Number = nv
	e.Value = sv
	return nil
}

func (e *DataParams) NumberValue() (int64, error) {
	return ParseNumber(e.Value)
}
