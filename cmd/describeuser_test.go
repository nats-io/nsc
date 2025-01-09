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

func TestDescribeUser_Single(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "a")

	pub := ts.GetUserPublicKey(t, "A", "a")
	apub := ts.GetAccountPublicKey(t, "A")

	out, err := ExecuteCmd(createDescribeUserCmd())
	require.NoError(t, err)
	// account A public key
	require.Contains(t, out.Out, apub)
	// operator public key
	require.Contains(t, out.Out, pub)
	// name for the account
	require.Contains(t, out.Out, " a ")
}

func TestDescribeUserRaw(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	Raw = true
	stdout, err := ExecuteCmd(createDescribeUserCmd())
	require.NoError(t, err)

	uc, err := jwt.DecodeUserClaims(stdout.Out)
	require.NoError(t, err)

	require.NotNil(t, uc)
	require.Equal(t, "U", uc.Name)
}

func TestDescribeUser_Multiple(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "a")
	ts.AddUser(t, "A", "b")

	stderr, err := ExecuteCmd(createDescribeUserCmd(), []string{}...)
	require.Error(t, err)
	require.Contains(t, stderr.Err, "user is required")
}

func TestDescribeUser_MultipleWithContext(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "a")
	ts.AddAccount(t, "B")
	ts.AddUser(t, "B", "b")

	err := GetConfig().SetAccount("B")
	require.NoError(t, err)

	apub := ts.GetAccountPublicKey(t, "B")

	pub := ts.GetUserPublicKey(t, "B", "b")

	out, err := ExecuteCmd(createDescribeUserCmd())
	require.NoError(t, err)
	require.Contains(t, out.Out, apub)
	require.Contains(t, out.Out, pub)
	require.Contains(t, out.Out, " b ")
}

func TestDescribeUser_MultipleWithFlag(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")
	ts.AddUser(t, "B", "b")
	ts.AddUser(t, "B", "bb")

	out, err := ExecuteCmd(createDescribeUserCmd(), "--account", "B")
	require.Error(t, err)
	require.Contains(t, out.Err, "user is required")

	apub := ts.GetAccountPublicKey(t, "B")

	pub := ts.GetUserPublicKey(t, "B", "bb")

	out, err = ExecuteCmd(createDescribeUserCmd(), "--account", "B", "--name", "bb")
	require.NoError(t, err)
	require.Contains(t, out.Out, apub)
	require.Contains(t, out.Out, pub)
	require.Contains(t, out.Out, " bb ")
}

func TestDescribeUser_MultipleWithBadUser(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")
	ts.AddUser(t, "B", "b")

	_, err := ExecuteCmd(createDescribeUserCmd(), []string{"--account", "A"}...)
	require.Error(t, err)

	_, err = ExecuteCmd(createDescribeUserCmd(), []string{"--account", "B", "--name", "a"}...)
	require.Error(t, err)

	_, err = ExecuteCmd(createDescribeUserCmd(), []string{"--account", "B", "--name", "b"}...)
	require.NoError(t, err)
}

func TestDescribeUser_Interactive(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")
	ts.AddUser(t, "B", "bb")

	_, err := ExecuteInteractiveCmd(createDescribeUserCmd(), []interface{}{1, 0})
	require.NoError(t, err)
}

func TestDescribeUser_Account(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, pub, kp := CreateAccountKey(t)
	_, err := ExecuteCmd(createEditAccount(), "--name", "A", "--sk", pub)
	require.NoError(t, err)

	// signed with default account key
	ts.AddUser(t, "A", "aa")
	out, err := ExecuteCmd(createDescribeUserCmd(), "--account", "A", "--name", "aa")
	require.NoError(t, err)
	require.NotContains(t, out.Out, "Issuer Account")

	// signed with a signing key
	ts.AddUserWithSigner(t, "A", "bb", kp)
	require.NoError(t, err)
	out, err = ExecuteCmd(createDescribeUserCmd(), "--account", "A", "--name", "bb")
	require.NoError(t, err)
	require.Contains(t, out.Out, "Issuer Account")
}

func TestDescribeRawUser(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, pub, kp := CreateAccountKey(t)
	_, err := ExecuteCmd(createEditAccount(), "--name", "A", "--sk", pub)
	require.NoError(t, err)

	// signed with default account key
	ts.AddUser(t, "A", "aa")
	out, err := ExecuteCmd(createDescribeUserCmd(), "--account", "A", "--name", "aa")
	require.NoError(t, err)
	require.NotContains(t, out.Out, "Issuer Account")

	// signed with a signing key
	ts.AddUserWithSigner(t, "A", "bb", kp)
	require.NoError(t, err)
	out, err = ExecuteCmd(createDescribeUserCmd(), "--account", "A", "--name", "bb")
	require.NoError(t, err)
	require.Contains(t, out.Out, "Issuer Account")
}

func TestDescribeUser_Json(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "aa")

	out, err := ExecuteCmd(rootCmd, "describe", "user", "--json")
	require.NoError(t, err)
	m := make(map[string]interface{})
	err = json.Unmarshal([]byte(out.Out), &m)
	require.NoError(t, err)
	uc, err := ts.Store.ReadUserClaim("A", "aa")
	require.NoError(t, err)
	require.NotNil(t, uc)
	require.Equal(t, uc.Subject, m["sub"])
}

func TestDescribeUser_JsonPath(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "aa")

	out, err := ExecuteCmd(rootCmd, "describe", "user", "--field", "sub")
	require.NoError(t, err)
	uc, err := ts.Store.ReadUserClaim("A", "aa")
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("\"%s\"\n", uc.Subject), out.Out)
}

func TestDescribeUser_Times(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "aa")
	_, err := ExecuteCmd(createEditUserCmd(), "--time", "16:04:05-17:04:09")
	require.NoError(t, err)

	out, err := ExecuteCmd(createDescribeUserCmd(), "--account", "A", "--name", "aa")
	require.NoError(t, err)
	require.Contains(t, out.Out, "16:04:05-17:04:09")
}

func TestDescribeUser_Output(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "aa")

	p := filepath.Join(ts.Dir, "aa.json")
	_, err := ExecuteCmd(rootCmd, []string{"describe", "user", "-a", "A", "--json", "--output-file", p}...)
	require.NoError(t, err)
	data, err := os.ReadFile(p)
	require.NoError(t, err)
	uc := jwt.UserClaims{}
	require.NoError(t, json.Unmarshal(data, &uc))
	require.Equal(t, "aa", uc.Name)

	p = filepath.Join(ts.Dir, "aa.txt")
	_, err = ExecuteCmd(rootCmd, []string{"describe", "user", "-a", "A", "--output-file", p}...)
	require.NoError(t, err)
	data, err = os.ReadFile(p)
	require.NoError(t, err)
	strings.Contains(string(data), "User Details")

	p = filepath.Join(ts.Dir, "aa.jwt")
	_, err = ExecuteCmd(rootCmd, []string{"describe", "user", "-a", "A", "--raw", "--output-file", p}...)
	require.NoError(t, err)
	data, err = os.ReadFile(p)
	require.NoError(t, err)
	require.Contains(t, string(data), "-----BEGIN NATS USER JWT-----\ney")
}
