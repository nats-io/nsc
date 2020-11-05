/*
 *
 *  * Copyright 2018-2020 The NATS Authors
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package cmd

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/stretchr/testify/require"
)

func TestDescribe(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	_, serr, err := ExecuteCmd(createDescribeJwtCmd())
	require.Error(t, err)
	require.Contains(t, serr, "file is required")
}

func TestDescribe_Operator(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	pub := ts.GetOperatorPublicKey(t)

	fp := filepath.Join(ts.GetStoresRoot(), "O", "O.jwt")
	out, _, err := ExecuteCmd(createDescribeJwtCmd(), "--file", fp)
	require.NoError(t, err)
	require.Contains(t, out, pub)
}

func TestDescribe_Interactive(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	pub := ts.GetAccountPublicKey(t, "A")

	fp := filepath.Join(ts.GetStoresRoot(), "O", store.Accounts, "A", "A.jwt")

	out, _, err := ExecuteInteractiveCmd(createDescribeJwtCmd(), []interface{}{fp})
	require.NoError(t, err)
	require.Contains(t, out, pub)
}

func TestDescribe_Account(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	pub := ts.GetAccountPublicKey(t, "A")

	fp := filepath.Join(ts.GetStoresRoot(), "O", store.Accounts, "A", "A.jwt")
	out, _, err := ExecuteCmd(createDescribeJwtCmd(), "--file", fp)
	require.NoError(t, err)
	require.Contains(t, out, pub)
}

func TestDescribe_User(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "a")
	pub := ts.GetUserPublicKey(t, "A", "a")

	fp := filepath.Join(ts.GetStoresRoot(), "O", store.Accounts, "A", store.Users, "a.jwt")
	out, _, err := ExecuteCmd(createDescribeJwtCmd(), "--file", fp)
	require.NoError(t, err)
	require.Contains(t, out, pub)
}

func TestDescribe_Activation(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	ts.AddExport(t, "A", jwt.Stream, "AA.>", false)

	token := ts.GenerateActivation(t, "A", "AA.>", "B")
	tp := filepath.Join(ts.Dir, "token.jwt")
	require.NoError(t, Write(tp, []byte(token)))

	out, _, err := ExecuteCmd(createDescribeJwtCmd(), "--file", tp)
	require.NoError(t, err)
	require.Contains(t, out, "AA.>")

	act, err := jwt.DecodeActivationClaims(token)
	require.NoError(t, err)

	hash, err := act.HashID()
	require.NoError(t, err)
	require.Contains(t, out, hash)
}

func TestDescribe_ActivationWithSigner(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	// generate an export, normally signed by the account
	ts.AddExport(t, "A", jwt.Stream, "AA.>", false)
	token := ts.GenerateActivation(t, "A", "AA.>", "B")
	tp := filepath.Join(ts.Dir, "token.jwt")
	require.NoError(t, Write(tp, []byte(token)))
	// verify that issuer account is not present
	out, _, err := ExecuteCmd(createDescribeJwtCmd(), "--file", tp)
	require.NoError(t, err)
	require.NotContains(t, out, "Issuer Account")
	// modify the account to have a signing key
	_, pk, kp := CreateAccountKey(t)
	_, _, err = ExecuteCmd(createEditAccount(), "-n", "A", "--sk", pk)
	require.NoError(t, err)
	// generate an export using the account signing key
	token = ts.GenerateActivationWithSigner(t, "A", "AA.>", "B", kp)
	tp2 := filepath.Join(ts.Dir, "token2.jwt")
	require.NoError(t, Write(tp2, []byte(token)))
	// verify that issuer account is present
	out, _, err = ExecuteCmd(createDescribeJwtCmd(), "--file", tp2)
	require.NoError(t, err)
	require.Contains(t, out, "Issuer Account")
}

func TestDescribeJwt_Json(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	fp := filepath.Join(ts.Store.Dir, "accounts", "A", "A.jwt")
	t.Log(fp)

	out, _, err := ExecuteCmd(rootCmd, "describe", "jwt", "--json", "--file", fp)
	require.NoError(t, err)
	m := make(map[string]interface{})
	err = json.Unmarshal([]byte(out), &m)
	require.NoError(t, err)
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, ac.Subject, m["sub"])
}

func TestDescribeJwt_JsonPath(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	fp := filepath.Join(ts.Store.Dir, "accounts", "A", "A.jwt")

	out, _, err := ExecuteCmd(rootCmd, "describe", "jwt", "--json", "--file", fp, "--field", "sub")
	require.NoError(t, err)
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("\"%s\"\n", ac.Subject), out)
}
