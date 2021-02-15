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
	"net/url"
	"os"
	"strings"
)

const EnvOperatorPrefix = "NSC_"
const EnvOperatorSuffix = "_OPERATOR"

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
		eo := fromEnv()
		if eo != nil {
			wellKnownOperators = append(wellKnownOperators, eo...)
		}
	}
	return wellKnownOperators, nil
}

// fromEnv returns operators in the environment named as `NSC_<name>_OPERATOR`
// the value on the environment should be an URL
func fromEnv() KnownOperators {
	return findEnvOperators(os.Environ())
}

func findEnvOperators(env []string) KnownOperators {
	pl := len(EnvOperatorPrefix)
	sl := len(EnvOperatorSuffix)
	var envOps KnownOperators
	for _, v := range env {
		pair := strings.Split(v, "=")
		k := strings.ToUpper(pair[0])
		if strings.HasPrefix(k, EnvOperatorPrefix) && strings.HasSuffix(k, EnvOperatorSuffix) {
			var envOp KnownOperator
			envOp.Name = pair[0][pl : len(pair[0])-sl]
			envOp.AccountServerURL = pair[1]
			envOps = append(envOps, envOp)
		}

	}
	return envOps
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

func GetOperatorName(name string, asu string) string {
	uv, err := url.Parse(asu)
	if err != nil {
		return name
	}
	hn := strings.ToLower(uv.Hostname())
	ops, err := GetWellKnownOperators()
	if err != nil {
		return name
	}
	for _, o := range ops {
		tu, err := url.Parse(o.AccountServerURL)
		if err == nil {
			h := strings.ToLower(tu.Hostname())
			if h == hn {
				return o.Name
			}
		}
	}
	return name

}
