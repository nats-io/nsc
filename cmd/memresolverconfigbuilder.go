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
	"bytes"
	"fmt"
	"sort"

	"github.com/nats-io/jwt"
)

type MemResolverConfigBuilder struct {
	claims map[string]string
}

func NewMemResolverConfigBuilder() *MemResolverConfigBuilder {
	cb := MemResolverConfigBuilder{}
	cb.claims = make(map[string]string)
	return &cb
}

func (cb *MemResolverConfigBuilder) Add(rawClaim []byte) error {
	token := string(rawClaim)
	gc, err := jwt.DecodeGeneric(token)
	if err != nil {
		return err
	}
	switch gc.Type {
	case jwt.AccountClaim:
		ac, err := jwt.DecodeAccountClaims(token)
		if err != nil {
			return err
		}
		cb.claims[ac.Subject] = token
	}
	return nil
}

func (cb *MemResolverConfigBuilder) Generate(ofp string) ([]byte, error) {
	var buf bytes.Buffer

	var keys []string
	for k := range cb.claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	if ofp != "" && ofp != "--" {
		buf.WriteString(fmt.Sprintf("operator: %q\n", ofp))
	} else if ofp == "--" {
		buf.WriteString("# operator: <specify_path_to_operator_jwt>\n")
	}
	buf.WriteString("resolver: MEMORY\n")
	buf.WriteString("resolver_preload: {\n")
	for _, k := range keys {
		v := cb.claims[k]
		buf.WriteString(fmt.Sprintf("  %s: %s\n", k, v))
	}
	buf.WriteString("}\n")
	return buf.Bytes(), nil
}
