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
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"sort"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"
)

type MemResolverConfigBuilder struct {
	operator   string
	claims     map[string]string
	pubToName  map[string]string
	dir        string
	sysAccount string
}

func NewMemResolverConfigBuilder() *MemResolverConfigBuilder {
	cb := MemResolverConfigBuilder{}
	cb.claims = make(map[string]string)
	cb.pubToName = make(map[string]string)
	return &cb
}

func (cb *MemResolverConfigBuilder) SetOutputDir(fp string) error {
	cb.dir = fp
	return nil
}

func (cb *MemResolverConfigBuilder) SetSystemAccount(id string) error {
	cb.sysAccount = id
	return nil
}

func (cb *MemResolverConfigBuilder) Add(rawClaim []byte) error {
	token := string(rawClaim)
	gc, err := jwt.DecodeGeneric(token)
	if err != nil {
		return err
	}
	switch gc.Type {
	case jwt.OperatorClaim:
		oc, err := jwt.DecodeOperatorClaims(token)
		if err != nil {
			return err
		}
		cb.operator = token
		cb.pubToName[oc.Subject] = oc.Name
		cb.pubToName["__OPERATOR__"] = oc.Subject
	case jwt.AccountClaim:
		ac, err := jwt.DecodeAccountClaims(token)
		if err != nil {
			return err
		}
		cb.claims[ac.Subject] = token
		cb.pubToName[ac.Subject] = ac.Name
	}
	return nil
}

func (cb *MemResolverConfigBuilder) GenerateConfig() ([]byte, error) {
	var buf bytes.Buffer

	opk := cb.pubToName["__OPERATOR__"]
	if opk == "" {
		return nil, errors.New("operator is not set")
	}
	buf.WriteString(fmt.Sprintf("// Operator %q\n", cb.pubToName[opk]))
	buf.WriteString(fmt.Sprintf("operator: %s\n\n", cb.operator))

	if cb.sysAccount != "" {
		buf.WriteString(fmt.Sprintf("system_account: %s\n\n", cb.sysAccount))
	}

	var keys []string
	for k := range cb.claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	buf.WriteString("resolver: MEMORY\n\n")
	buf.WriteString("resolver_preload: {\n")
	for _, k := range keys {
		v := cb.claims[k]
		buf.WriteString(fmt.Sprintf("  // Account %q\n", cb.pubToName[k]))
		buf.WriteString(fmt.Sprintf("  %s: %s\n\n", k, v))
	}
	buf.WriteString("}\n")
	return buf.Bytes(), nil
}

func (cb *MemResolverConfigBuilder) writeFile(dir string, name string, token string) (string, error) {
	fp := filepath.Join(dir, store.JwtName(name))
	err := ioutil.WriteFile(fp, []byte(token), 0666)
	return fp, err
}

func (cb *MemResolverConfigBuilder) GenerateDir() ([]byte, error) {
	var buf bytes.Buffer

	if err := MaybeMakeDir(cb.dir); err != nil {
		return nil, err
	}

	opk := cb.pubToName["__OPERATOR__"]
	if opk == "" {
		return nil, errors.New("operator is not set")
	}

	fn, err := cb.writeFile(cb.dir, cb.pubToName[opk], cb.operator)
	if err != nil {
		return nil, err
	}
	buf.WriteString(fmt.Sprintf("// Operator %q\n", cb.pubToName[opk]))
	buf.WriteString(fmt.Sprintf("operator: %q\n\n", filepath.Join(".", filepath.Base(fn))))

	if cb.sysAccount != "" {
		buf.WriteString(fmt.Sprintf("system_account: %s\n\n", cb.sysAccount))
	}

	var keys []string
	for k := range cb.claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	buf.WriteString("resolver: MEMORY\n\n")
	buf.WriteString("resolver_preload: {\n")
	for _, k := range keys {
		v := cb.claims[k]
		n := cb.pubToName[k]
		buf.WriteString(fmt.Sprintf("  // Account %q\n", n))
		fn, err := cb.writeFile(cb.dir, n, v)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(cb.dir, fn)
		if err != nil {
			return nil, err
		}
		buf.WriteString(fmt.Sprintf("  %s: %q\n\n", k, rel))
	}
	buf.WriteString("}\n")

	err = ioutil.WriteFile(filepath.Join(cb.dir, "resolver.conf"), buf.Bytes(), 0666)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (cb *MemResolverConfigBuilder) Generate() ([]byte, error) {
	if cb.dir != "" {
		return cb.GenerateDir()
	}
	return cb.GenerateConfig()
}
