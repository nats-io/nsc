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

	"github.com/dustin/go-humanize"

	cli "github.com/nats-io/cliprompts/v2"
)

type NumberParams int64

func (e *NumberParams) Valid() error {
	// flag already insures this is a number
	return nil
}

func (e *NumberParams) Edit(prompt string) error {
	var err error
	var nv int64
	sv := fmt.Sprintf("%d", e)
	_, err = cli.Prompt(prompt, sv, cli.Val(func(s string) error {
		nv, err = ParseNumber(s)
		return err
	}))
	if err != nil {
		return err
	}
	*e = NumberParams(nv)
	return nil
}

func (e *NumberParams) Set(s string) error {
	nv, err := ParseNumber(s)
	if err != nil {
		return err
	}
	*e = NumberParams(nv)
	return nil
}

func (e *NumberParams) Type() string {
	return "number"
}

func (e *NumberParams) String() string {
	return humanize.Comma(int64(*e))
}

func (e *NumberParams) Int64() int64 {
	return int64(*e)
}
