/*
 * Copyright 2020-2025 The NATS Authors
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
	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_RenameAccountRequiresOK(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	_, err := ExecuteCmd(createRenameAccountCmd(), []string{"A", "B"}...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "required flag \"OK\" not set")
}

func Test_RenameAccountNoUsers(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	pk := ts.GetAccountPublicKey(t, "A")
	_, err := ExecuteCmd(createRenameAccountCmd(), []string{"A", "B", "--OK"}...)
	require.NoError(t, err)

	_, err = ts.Store.ReadAccountClaim("A")
	require.Error(t, err)

	bc, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Equal(t, "B", bc.Name)
	require.Equal(t, pk, bc.Subject)
}

func Test_RenameAccountUsers(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "aa")
	ts.AddUser(t, "A", "bb")
	pk := ts.GetAccountPublicKey(t, "A")
	require.FileExists(t, ts.KeyStore.CalcUserCredsPath("A", "aa"))
	require.FileExists(t, ts.KeyStore.CalcUserCredsPath("A", "bb"))

	_, err := ExecuteCmd(createRenameAccountCmd(), []string{"A", "B", "--OK"}...)
	require.NoError(t, err)

	_, err = ts.Store.ReadAccountClaim("A")
	require.Error(t, err)

	bc, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Equal(t, "B", bc.Name)
	require.Equal(t, pk, bc.Subject)
	require.FileExists(t, ts.KeyStore.CalcUserCredsPath("B", "aa"))
	require.FileExists(t, ts.KeyStore.CalcUserCredsPath("B", "bb"))
	ts.DoesNotExist(t, ts.KeyStore.CalcUserCredsPath("A", "aa"))
	ts.DoesNotExist(t, ts.KeyStore.CalcUserCredsPath("A", "bb"))
}

func Test_RenameAccountDuplicate(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	_, err := ExecuteCmd(createRenameAccountCmd(), []string{"A", "B", "--OK"}...)
	require.Error(t, err)
}

func Test_RenameManagedAccount(t *testing.T) {
	as, m := RunTestAccountServer(t)
	defer as.Close()

	ts := NewTestStoreWithOperatorJWT(t, string(m["operator"]))
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	pk := ts.GetAccountPublicKey(t, "A")
	ac, err := jwt.DecodeAccountClaims(string(m[pk]))
	require.NoError(t, err)
	require.Equal(t, pk, ac.Subject)
	require.Equal(t, "A", ac.Name)

	_, err = ExecuteCmd(createRenameAccountCmd(), []string{"A", "B", "--OK"}...)
	require.NoError(t, err)
	bc, err := jwt.DecodeAccountClaims(string(m[pk]))
	require.NoError(t, err)
	require.Equal(t, pk, bc.Subject)
	require.Equal(t, "B", bc.Name)
}
