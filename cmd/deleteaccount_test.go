/*
 * Copyright 2019-2025 The NATS Authors
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
	"os"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/require"
)

func Test_DeleteAccountNotFound(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, err := ExecuteCmd(createDeleteAccountCmd(), []string{"--name", "B"}...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "\"B\" not in accounts for operator \"O\"")
}

func Test_DeleteAccountOnly(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	apk := ac.Subject

	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	upk := uc.Subject

	_, err = ExecuteCmd(createDeleteAccountCmd(), []string{"A"}...)
	require.NoError(t, err)
	require.True(t, ts.KeyStore.HasPrivateKey(apk))
	require.True(t, ts.KeyStore.HasPrivateKey(upk))
	require.FileExists(t, ts.KeyStore.GetUserCredsPath("A", "U"))
}

func Test_DeleteAll(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	_, pk, kp := CreateAccountKey(t)
	ts.KeyStore.Store(kp)
	ts.AddAccount(t, "A")

	_, err := ExecuteCmd(createEditAccount(), []string{"--sk", pk}...)
	require.NoError(t, err)

	ts.AddUser(t, "A", "U")

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	apk := ac.Subject

	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	upk := uc.Subject

	_, err = ExecuteCmd(createDeleteAccountCmd(), []string{"A", "--rm-nkey", "--rm-creds"}...)
	require.NoError(t, err)
	require.False(t, ts.KeyStore.HasPrivateKey(apk))
	require.False(t, ts.KeyStore.HasPrivateKey(pk))
	require.False(t, ts.KeyStore.HasPrivateKey(upk))
	_, err = os.Stat(ts.KeyStore.GetUserCredsPath("A", "U"))
	require.True(t, os.IsNotExist(err))
}

func Test_DeleteAccountInteractive(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	apk := ac.Subject

	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	upk := uc.Subject

	_, err = ExecuteInteractiveCmd(createDeleteAccountCmd(), []interface{}{false, true, true, true}, "--name", "A")
	require.NoError(t, err)

	uc, err = ts.Store.ReadUserClaim("A", "U")
	require.Error(t, err)
	require.Nil(t, uc)

	require.False(t, ts.KeyStore.HasPrivateKey(apk))
	require.False(t, ts.KeyStore.HasPrivateKey(upk))
	_, err = os.Stat(ts.KeyStore.GetUserCredsPath("A", "U"))
	require.True(t, os.IsNotExist(err))
}

func Test_DeleteManagedAccountRequiresForceAndExpires(t *testing.T) {
	as, m := RunTestAccountServer(t)
	defer as.Close()

	ts := NewTestStoreWithOperatorJWT(t, string(m["operator"]))
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	_, err := ExecuteCmd(createDeleteAccountCmd(), []string{"A"}...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "--force to override")

	ts.AddAccount(t, "A")
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Zero(t, ac.Expires)
	_, err = ExecuteCmd(createDeleteAccountCmd(), []string{"A", "--force"}...)
	require.NoError(t, err)

	token := m[ac.Subject]
	require.NotNil(t, token)

	eac, err := jwt.DecodeAccountClaims(string(token))
	require.NoError(t, err)
	require.NotZero(t, eac.Expires)
	require.Len(t, eac.Revocations, 1)
}
