// Copyright 2018-2025 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nats-io/jwt/v2"

	"github.com/stretchr/testify/require"
)

func TestDescribeOperator_Single(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	pub := ts.GetOperatorPublicKey(t)
	out, err := ExecuteCmd(createDescribeOperatorCmd())
	require.NoError(t, err)
	require.Contains(t, out.Out, pub)
	require.Contains(t, out.Out, " operator ")
}

func TestDescribeOperator_Raw(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)
	oldRaw := Raw
	Raw = true
	defer func() {
		Raw = oldRaw
	}()

	stdout, err := ExecuteCmd(createDescribeOperatorCmd())
	require.NoError(t, err)

	oc, err := jwt.DecodeOperatorClaims(stdout.Out)
	require.NoError(t, err)

	require.NotNil(t, oc)
	require.Equal(t, "operator", oc.Name)
}

func TestDescribeOperator_Multiple(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddOperator(t, "A")

	_, err := ExecuteCmd(createDescribeOperatorCmd(), []string{}...)
	require.NoError(t, err)
}

func TestDescribeOperator_MultipleWithContext(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddOperator(t, "A")
	ts.AddOperator(t, "B")

	err := GetConfig().SetOperator("B")
	require.NoError(t, err)

	pub := ts.GetOperatorPublicKey(t)

	stdout, err := ExecuteCmd(createDescribeOperatorCmd())
	require.NoError(t, err)
	require.Contains(t, stdout.Out, pub)
	require.Contains(t, stdout.Out, " B ")
}

func TestDescribeOperator_MultipleWithFlag(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddOperator(t, "A")
	ts.AddOperator(t, "B")

	pub := ts.GetOperatorPublicKey(t)

	stdout, err := ExecuteCmd(createDescribeOperatorCmd(), "--name", "B")
	require.NoError(t, err)
	require.Contains(t, stdout.Out, " B ")
	require.Contains(t, stdout.Out, pub)
}

func TestDescribeOperator_MultipleWithBadOperator(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	_, err := ExecuteCmd(createDescribeOperatorCmd(), []string{"--name", "C"}...)
	require.Error(t, err)
}

func TestDescribeOperator_AccountServerURL(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	stdout, err := ExecuteCmd(createDescribeOperatorCmd(), []string{"--name", "O"}...)
	require.NoError(t, err)
	require.NotContains(t, stdout.Out, "Account JWT Server")

	u := "https://asu.com:1234"
	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.NotNil(t, oc)
	oc.AccountServerURL = u
	token, err := oc.Encode(ts.OperatorKey)
	require.NoError(t, err)
	err = ts.Store.StoreRaw([]byte(token))
	require.NoError(t, err)

	stdout, err = ExecuteCmd(createDescribeOperatorCmd(), "--name", "O")
	require.NoError(t, err)
	require.Contains(t, stdout.Out, u)
}

func TestDescribeOperator_OperatorServiceURLs(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	out, err := ExecuteCmd(createDescribeOperatorCmd(), "--name", "O")
	require.NoError(t, err)
	require.NotContains(t, out.Out, "Operator Service URLs")

	urls := []string{"nats://localhost:4222", "tls://localhost:4333"}
	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	oc.OperatorServiceURLs.Add(urls...)

	token, err := oc.Encode(ts.OperatorKey)
	require.NoError(t, err)
	_, err = ts.Store.StoreClaim([]byte(token))
	require.NoError(t, err)

	out, err = ExecuteCmd(createDescribeOperatorCmd(), "--name", "O")
	require.NoError(t, err)
	require.Contains(t, out.Out, "Operator Service URLs")
	require.Contains(t, out.Out, "nats://localhost:4222")
	require.Contains(t, out.Out, "tls://localhost:4333")
}

func TestDescribeOperator_Json(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	out, err := ExecuteCmd(rootCmd, "describe", "operator", "--json")
	require.NoError(t, err)
	m := make(map[string]interface{})
	err = json.Unmarshal([]byte(out.Out), &m)
	require.NoError(t, err)
	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.NotNil(t, oc)
	require.Equal(t, oc.Subject, m["sub"])
}

func TestDescribeOperator_JsonPath(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	out, err := ExecuteCmd(rootCmd, "describe", "operator", "--field", "sub")
	require.NoError(t, err)
	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("\"%s\"\n", oc.Subject), out.Out)
}

func TestDescribeOperator_Output(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	p := filepath.Join(ts.Dir, "O.json")
	_, err := ExecuteCmd(rootCmd, []string{"describe", "operator", "--json", "--output-file", p}...)
	require.NoError(t, err)
	data, err := os.ReadFile(p)
	require.NoError(t, err)

	oc := jwt.OperatorClaims{}
	require.NoError(t, json.Unmarshal(data, &oc))
	require.Equal(t, "O", oc.Name)

	p = filepath.Join(ts.Dir, "O.txt")
	_, err = ExecuteCmd(rootCmd, []string{"describe", "operator", "--output-file", p}...)
	require.NoError(t, err)
	data, err = os.ReadFile(p)
	require.NoError(t, err)
	strings.Contains(string(data), "Operator Details")

	p = filepath.Join(ts.Dir, "O.jwt")
	_, err = ExecuteCmd(rootCmd, []string{"describe", "operator", "--raw", "--output-file", p}...)
	require.NoError(t, err)
	data, err = os.ReadFile(p)
	require.NoError(t, err)
	require.Contains(t, string(data), "-----BEGIN NATS OPERATOR JWT-----\ney")
}
