/*
 * Copyright 2018-2025 The NATS Authors
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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
)

var (
	Raw      bool
	WideFlag bool
	Wide     = noopNameFilter
	Json     bool
	JsonPath string
)

type WideFun = func(a string) string

func noopNameFilter(a string) string {
	return a
}

func friendlyNameFilter() (WideFun, error) {
	m, err := friendlyNames(GetConfig().Operator)
	if err != nil {
		return nil, err
	}
	return func(a string) string {
		v := m[a]
		if v == "" {
			v = a
		}
		return v
	}, nil
}

var describeCmd = &cobra.Command{
	Use:   "describe",
	Short: "Describe assets such as operators, accounts, users, and jwt files",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// run the roots PersistentPreRun
		if err := GetRootCmd().PersistentPreRunE(cmd, args); err != nil {
			return err
		}
		var err error
		if WideFlag {
			Wide = noopNameFilter
		} else {
			Wide, err = friendlyNameFilter()
			if err != nil {
				return err
			}
		}
		return nil
	},
}

func init() {
	GetRootCmd().AddCommand(describeCmd)
	describeCmd.PersistentFlags().BoolVarP(&Json, "json", "J", false, "display JWT body as JSON")
	describeCmd.PersistentFlags().BoolVarP(&WideFlag, "long-ids", "W", false, "display account ids on imports")
	describeCmd.PersistentFlags().BoolVarP(&Raw, "raw", "R", false, "output the raw JWT (exclusive of long-ids)")
	describeCmd.PersistentFlags().StringVarP(&JsonPath, "field", "F", "", "extract value from specified field using json structure")
}

func bodyAsJson(data []byte) ([]byte, error) {
	chunks := bytes.Split(data, []byte{'.'})
	if len(chunks) != 3 {
		return nil, errors.New("data is not a jwt")
	}
	body := chunks[1]
	d, err := base64.RawURLEncoding.DecodeString(string(body))
	if err != nil {
		return nil, fmt.Errorf("error decoding base64: %v", err)
	}
	m := make(map[string]interface{})
	if err := json.Unmarshal(d, &m); err != nil {
		return nil, fmt.Errorf("error parsing json: %v", err)
	}

	j := &bytes.Buffer{}
	encoder := json.NewEncoder(j)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", " ")
	if err := encoder.Encode(m); err != nil {
		return nil, fmt.Errorf("error formatting json: %v", err)
	}
	return j.Bytes(), nil
}

type BaseDescribe struct {
	raw        []byte
	kind       jwt.ClaimType
	outputFile string
}

func (p *BaseDescribe) Init() error {
	token, err := jwt.ParseDecoratedJWT(p.raw)
	if err != nil {
		return err
	}
	p.raw = []byte(token)
	gc, err := jwt.DecodeGeneric(token)
	if err != nil {
		return err
	}
	p.kind = gc.ClaimType()
	return nil
}

func (p *BaseDescribe) Describe(ctx ActionCtx) (store.Status, error) {
	var out []byte
	var err error

	if Raw {
		out, err = p.Raw(!IsStdOut(p.outputFile))
	} else if Json || JsonPath != "" {
		out, err = p.JSON(JsonPath)
	} else {
		out, err = p.Structured()
	}
	if err != nil {
		return nil, err
	}
	if IsStdOut(p.outputFile) {
		_, err = fmt.Fprintln(ctx.CurrentCmd().OutOrStdout(), string(out))
	} else {
		err = WriteFile(p.outputFile, out)
	}
	if err != nil {
		return nil, err
	}
	if !IsStdOut(p.outputFile) {
		k := "description"
		if Raw {
			k = "jwt"
		}
		return store.OKStatus("wrote %s %s to %#q", string(p.kind), k, AbbrevHomePaths(p.outputFile)), nil
	}
	return nil, err
}

func (p *BaseDescribe) Structured() ([]byte, error) {
	var describer Describer
	switch p.kind {
	case jwt.AccountClaim:
		ac, err := jwt.DecodeAccountClaims(string(p.raw))
		if err != nil {
			return []byte(""), err
		}
		describer = NewAccountDescriber(*ac)
	case jwt.ActivationClaim:
		ac, err := jwt.DecodeActivationClaims(string(p.raw))
		if err != nil {
			return []byte(""), err
		}
		describer = NewActivationDescriber(*ac)
	case jwt.UserClaim:
		uc, err := jwt.DecodeUserClaims(string(p.raw))
		if err != nil {
			return []byte(""), err
		}
		describer = NewUserDescriber(*uc)
	case jwt.OperatorClaim:
		oc, err := jwt.DecodeOperatorClaims(string(p.raw))
		if err != nil {
			return []byte(""), err
		}
		describer = NewOperatorDescriber(*oc)
	}

	if describer == nil {
		return []byte(""), fmt.Errorf("describer for %q is not implemented", p.kind)
	}
	return []byte(describer.Describe()), nil
}

func (p *BaseDescribe) Raw(decorate bool) ([]byte, error) {
	if decorate {
		return jwt.DecorateJWT(string(p.raw))
	}
	return p.raw, nil
}

func (p *BaseDescribe) JSON(jsonPath string) ([]byte, error) {
	raw, err := bodyAsJson(p.raw)
	if err != nil {
		return nil, err
	}
	if jsonPath != "" {
		raw, err = GetField(raw, JsonPath)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}
