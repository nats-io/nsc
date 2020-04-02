/*
 * Copyright 2018-2020 The NATS Authors
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
	"encoding/json"
	"fmt"
	"testing"

	"github.com/nats-io/jwt"

	"github.com/stretchr/testify/require"
)

func TestDescribeUser_Single(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "a")

	pub := ts.GetUserPublicKey(t, "A", "a")
	apub := ts.GetAccountPublicKey(t, "A")

	stdout, _, err := ExecuteCmd(createDescribeUserCmd())
	require.NoError(t, err)
	// account A public key
	require.Contains(t, stdout, apub)
	// operator public key
	require.Contains(t, stdout, pub)
	// name for the account
	require.Contains(t, stdout, " a ")
}

func TestDescribeUserRaw(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	Raw = true
	stdout, _, err := ExecuteCmd(createDescribeUserCmd())
	require.NoError(t, err)

	uc, err := jwt.DecodeUserClaims(stdout)
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

	_, stderr, err := ExecuteCmd(createDescribeUserCmd())
	require.Error(t, err)
	require.Contains(t, stderr, "user is required")
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

	stdout, _, err := ExecuteCmd(createDescribeUserCmd())
	require.NoError(t, err)
	require.Contains(t, stdout, apub)
	require.Contains(t, stdout, pub)
	require.Contains(t, stdout, " b ")
}

func TestDescribeUser_MultipleWithFlag(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")
	ts.AddUser(t, "B", "b")
	ts.AddUser(t, "B", "bb")

	_, stderr, err := ExecuteCmd(createDescribeUserCmd(), "--account", "B")
	require.Error(t, err)
	require.Contains(t, stderr, "user is required")

	apub := ts.GetAccountPublicKey(t, "B")

	pub := ts.GetUserPublicKey(t, "B", "bb")

	stdout, _, err := ExecuteCmd(createDescribeUserCmd(), "--account", "B", "--name", "bb")
	require.NoError(t, err)
	require.Contains(t, stdout, apub)
	require.Contains(t, stdout, pub)
	require.Contains(t, stdout, " bb ")
}

func TestDescribeUser_MultipleWithBadUser(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")
	ts.AddUser(t, "B", "b")

	_, _, err := ExecuteCmd(createDescribeUserCmd(), "--account", "A")
	require.Error(t, err)

	_, _, err = ExecuteCmd(createDescribeUserCmd(), "--account", "B", "--name", "a")
	require.Error(t, err)

	_, _, err = ExecuteCmd(createDescribeUserCmd(), "--account", "B", "--name", "b")
	require.NoError(t, err)
}

func TestDescribeUser_Interactive(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")
	ts.AddUser(t, "B", "bb")

	_, _, err := ExecuteInteractiveCmd(createDescribeUserCmd(), []interface{}{1, 0})
	require.NoError(t, err)
}

func TestDescribeUser_Account(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, pub, kp := CreateAccountKey(t)
	_, _, err := ExecuteCmd(createEditAccount(), "--name", "A", "--sk", pub)
	require.NoError(t, err)

	// signed with default account key
	ts.AddUser(t, "A", "aa")
	stdout, _, err := ExecuteCmd(createDescribeUserCmd(), "--account", "A", "--name", "aa")
	require.NoError(t, err)
	require.NotContains(t, stdout, "Issuer Account")

	// signed with a signing key
	ts.AddUserWithSigner(t, "A", "bb", kp)
	require.NoError(t, err)
	stdout, _, err = ExecuteCmd(createDescribeUserCmd(), "--account", "A", "--name", "bb")
	require.NoError(t, err)
	require.Contains(t, stdout, "Issuer Account")
}

func TestDescribeRawUser(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, pub, kp := CreateAccountKey(t)
	_, _, err := ExecuteCmd(createEditAccount(), "--name", "A", "--sk", pub)
	require.NoError(t, err)

	// signed with default account key
	ts.AddUser(t, "A", "aa")
	stdout, _, err := ExecuteCmd(createDescribeUserCmd(), "--account", "A", "--name", "aa")
	require.NoError(t, err)
	require.NotContains(t, stdout, "Issuer Account")

	// signed with a signing key
	ts.AddUserWithSigner(t, "A", "bb", kp)
	require.NoError(t, err)
	stdout, _, err = ExecuteCmd(createDescribeUserCmd(), "--account", "A", "--name", "bb")
	require.NoError(t, err)
	require.Contains(t, stdout, "Issuer Account")
}

func TestDescribeUser_Json(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "aa")

	out, _, err := ExecuteCmd(rootCmd, "describe", "user", "--json")
	require.NoError(t, err)
	m := make(map[string]interface{})
	err = json.Unmarshal([]byte(out), &m)
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

	out, _, err := ExecuteCmd(rootCmd, "describe", "user", "--field", "sub")
	uc, err := ts.Store.ReadUserClaim("A", "aa")
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("\"%s\"\n", uc.Subject), out)
}
