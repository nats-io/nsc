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
	"strings"
)

type KnownOperator struct {
	Name             string `json:"name"`
	URL              string `json:"url"`
	AccountServerURL string `json:"account_server_url"`
}

type KnownOperators []KnownOperator

var wellKnownOperators KnownOperators

func defaultWellKnownOperators() KnownOperators {
	return KnownOperators{
		{Name: "synadia", URL: "https://www.synadia.com", AccountServerURL: "https://api.synadia.io/jwt/v1/synadia"},
	}
}

func GetWellKnownOperators() (KnownOperators, error) {
	if wellKnownOperators == nil {
		wellKnownOperators = defaultWellKnownOperators()
	}
	return wellKnownOperators, nil
}

func FindKnownOperator(name string) (*KnownOperator, error) {
	a, err := GetWellKnownOperators()
	if err != nil {
		return nil, err
	}
	name = strings.ToLower(name)
	for _, v := range a {
		n := strings.ToLower(v.Name)
		if n == name {
			c := v
			return &c, nil
		}
	}
	return nil, nil
}
