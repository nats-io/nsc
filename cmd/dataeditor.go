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
	"regexp"
	"strconv"
	"strings"

	"github.com/nats-io/nsc/cli"
)

type DataEditor struct {
	flagValue *string
}

func NewDataEditor(v *string) *DataEditor {
	return &DataEditor{flagValue: v}
}

func (e *DataEditor) Valid() error {
	_, err := ParseDataSize(*e.flagValue)
	return err
}

func (e *DataEditor) Edit(prompt string) error {
	var err error
	*e.flagValue, err = cli.Prompt(prompt, *e.flagValue, true, func(s string) error {
		_, err := ParseDataSize(*e.flagValue)
		return err
	})
	return err
}

func ParseDataSize(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	s = strings.ToUpper(s)
	re := regexp.MustCompile(`(\d+$)`)
	m := re.FindStringSubmatch(s)
	if m != nil {
		v, err := strconv.ParseInt(m[0], 10, 64)
		if err != nil {
			return 0, err
		}
		return v, nil
	}
	re = regexp.MustCompile(`(\d+)([B|K|M])`)
	m = re.FindStringSubmatch(s)
	if m != nil {
		v, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			return 0, err
		}
		if m[2] == "B" {
			return v, nil
		}
		if m[2] == "K" {
			return v * 1000, nil
		}
		if m[2] == "M" {
			return v * 1000000, nil
		}
	}
	return 0, fmt.Errorf("couldn't parse data size: %v", s)
}
