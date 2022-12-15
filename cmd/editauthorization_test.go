/*
 * Copyright 2022 The NATS Authors
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
	"fmt"
	"testing"

	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func Test_EditAuthorizationNoFlags(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	_, _, err := ExecuteCmd(createEditAuthorizationCallout())
	require.Error(t, err)
	require.Equal(t, "please specify some options", err.Error())
}

func Test_EditAuthorizationBadUser(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	_, aPK, _ := CreateAccountKey(t)
	_, _, err := ExecuteCmd(createEditAuthorizationCallout(), "--auth-user", aPK)
	require.Error(t, err)
	require.Equal(t, fmt.Sprintf("%s is not a valid user key", aPK), err.Error())
}

func Test_EditAuthorizationBadAccount(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	_, aPK, _ := CreateUserKey(t)
	_, _, err := ExecuteCmd(createEditAuthorizationCallout(), "--allowed-account", aPK)
	require.Error(t, err)
	require.Equal(t, fmt.Sprintf("%s is not a valid account key", aPK), err.Error())
}

func Test_EditAuthorizationJustUser(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	_, uPK, _ := CreateUserKey(t)
	_, _, err := ExecuteCmd(createEditAuthorizationCallout(), "--auth-user", uPK)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.Authorization.AuthUsers, uPK)
}

func Test_EditAuthorizationJustAccount(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	_, aPK, _ := CreateAccountKey(t)
	_, _, err := ExecuteCmd(createEditAuthorizationCallout(), "--allowed-account", aPK)
	require.Error(t, err)
	require.Contains(t, err.Error(), "External authorization cannot have accounts without users specified")
}

func Test_EditAuthorizationDelete(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	_, uPK, _ := CreateUserKey(t)
	_, aPK, _ := CreateAccountKey(t)
	_, _, err := ExecuteCmd(createEditAuthorizationCallout(), "--auth-user", uPK, "--allowed-account", aPK)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.Authorization.AuthUsers, uPK)
	require.Contains(t, ac.Authorization.AllowedAccounts, aPK)

	_, _, err = ExecuteCmd(createEditAuthorizationCallout(), "--disable")
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Empty(t, ac.Authorization.AuthUsers)
	require.Empty(t, ac.Authorization.AllowedAccounts)
}

func Test_EditAuthorizationDeleteUser(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	_, uPK, _ := CreateUserKey(t)
	_, u2PK, _ := CreateUserKey(t)
	_, aPK, _ := CreateAccountKey(t)
	_, a2PK, _ := CreateAccountKey(t)
	_, _, err := ExecuteCmd(createEditAuthorizationCallout(),
		"--auth-user", fmt.Sprintf("%s,%s", uPK, u2PK),
		"--allowed-account", fmt.Sprintf("%s,%s", aPK, a2PK))
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.Authorization.AuthUsers, uPK)
	require.Contains(t, ac.Authorization.AuthUsers, u2PK)
	require.Contains(t, ac.Authorization.AllowedAccounts, aPK)
	require.Contains(t, ac.Authorization.AllowedAccounts, a2PK)

	_, _, err = ExecuteCmd(createEditAuthorizationCallout(),
		"--rm-auth-user", u2PK,
		"--rm-allowed-account", a2PK)
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.Authorization.AuthUsers, uPK)
	require.NotContains(t, ac.Authorization.AuthUsers, u2PK)
	require.Contains(t, ac.Authorization.AllowedAccounts, aPK)
	require.NotContains(t, ac.Authorization.AllowedAccounts, a2PK)
}

func Test_EditAuthorizationCurveKey(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	_, uPK, _ := CreateUserKey(t)
	_, u2PK, _ := CreateUserKey(t)
	_, aPK, _ := CreateAccountKey(t)
	_, a2PK, _ := CreateAccountKey(t)
	_, _, err := ExecuteCmd(createEditAuthorizationCallout(),
		"--auth-user", fmt.Sprintf("%s,%s", uPK, u2PK),
		"--allowed-account", fmt.Sprintf("%s,%s", aPK, a2PK),
		"--curve", "generate")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.Authorization.AuthUsers, uPK)
	require.Contains(t, ac.Authorization.AuthUsers, u2PK)
	require.Contains(t, ac.Authorization.AllowedAccounts, aPK)
	require.Contains(t, ac.Authorization.AllowedAccounts, a2PK)
	require.NotEmpty(t, ac.Authorization.XKey)
	require.True(t, nkeys.IsValidPublicCurveKey(ac.Authorization.XKey))

	// find the key in the store
	kp, err := ts.KeyStore.GetKeyPair(ac.Authorization.XKey)
	require.NoError(t, err)
	sx, err := kp.Seed()
	require.NoError(t, err)
	assert.Equal(t, "SX", string(sx[0:2]))

	_, _, err = ExecuteCmd(createEditAuthorizationCallout(),
		"--rm-auth-user", u2PK,
		"--rm-allowed-account", a2PK,
		"--rm-curve")
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.Authorization.AuthUsers, uPK)
	require.NotContains(t, ac.Authorization.AuthUsers, u2PK)
	require.Contains(t, ac.Authorization.AllowedAccounts, aPK)
	require.NotContains(t, ac.Authorization.AllowedAccounts, a2PK)
	require.Empty(t, ac.Authorization.XKey)
}
