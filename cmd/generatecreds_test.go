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
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestGenerateConfig_Default(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "u")

	accountJwt, err := ts.Store.Read(store.Accounts, "A", store.Users, "u.jwt")
	require.NoError(t, err)

	seed := ts.GetUserSeedKey(t, "A", "u")
	require.NoError(t, err)

	out, err := ExecuteCmd(createGenerateCredsCmd())
	require.NoError(t, err)
	require.Contains(t, out.Out, string(accountJwt))
	require.Contains(t, out.Out, seed)
}

func TestGenerateConfig_MultipleAccounts(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "B")
	ts.AddUser(t, "B", "u")
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "u")

	accountJwt, err := ts.Store.Read(store.Accounts, "A", store.Users, "u.jwt")
	require.NoError(t, err)

	seed := ts.GetUserSeedKey(t, "A", "u")
	require.NoError(t, err)

	out, err := ExecuteCmd(createGenerateCredsCmd(), []string{}...)
	require.NoError(t, err)
	require.Contains(t, out.Out, string(accountJwt))
	require.Contains(t, out.Out, seed)
}

func TestGenerateConfig_MultipleAccountsAccountRequired(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")
	ts.AddUser(t, "A", "u")
	ts.AddUser(t, "B", "u")

	GetConfig().SetAccount("")
	_, err := ExecuteCmd(createGenerateCredsCmd(), []string{}...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "account is required")
}

func TestGenerateConfig_MultipleUsers(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "u")
	ts.AddUser(t, "A", "uu")

	accountJwt, err := ts.Store.Read(store.Accounts, "A", store.Users, "u.jwt")
	require.NoError(t, err)

	seed := ts.GetUserSeedKey(t, "A", "u")
	require.NoError(t, err)

	_, err = ExecuteCmd(createGenerateCredsCmd(), []string{}...)
	require.Error(t, err)
	require.Equal(t, "user is required", err.Error())

	stdout, err := ExecuteCmd(createGenerateCredsCmd(), []string{"--account", "A", "--name", "u"}...)
	require.NoError(t, err)
	require.Contains(t, stdout.Out, string(accountJwt))
	require.Contains(t, stdout.Out, seed)
}

func TestGenerateConfig_Interactive(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")
	ts.AddUser(t, "A", "u")
	ts.AddUser(t, "A", "uu")

	accountJwt, err := ts.Store.Read(store.Accounts, "A", store.Users, "u.jwt")
	require.NoError(t, err)

	seed := ts.GetUserSeedKey(t, "A", "u")
	stdout, err := ExecuteInteractiveCmd(createGenerateCredsCmd(), []interface{}{0, 0})
	require.NoError(t, err)
	require.Contains(t, stdout.Out, string(accountJwt))
	require.Contains(t, stdout.Out, seed)
}

func TestGenerateConfig_HonorsAccount(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "au")
	ts.AddAccount(t, "B")
	ts.AddUser(t, "B", "bu")

	out, err := ExecuteCmd(createGenerateCredsCmd(), []string{"--account", "A"}...)
	require.NoError(t, err)
	userToken, err := jwt.ParseDecoratedJWT([]byte(out.Out))
	require.NoError(t, err)

	uc, err := jwt.DecodeUserClaims(userToken)
	require.NoError(t, err)
	require.Equal(t, "au", uc.Name)

	out, err = ExecuteCmd(createGenerateCredsCmd(), []string{"--account", "B"}...)
	require.NoError(t, err)
	userToken, err = jwt.ParseDecoratedJWT([]byte(out.Out))
	require.NoError(t, err)

	uc, err = jwt.DecodeUserClaims(userToken)
	require.NoError(t, err)
	require.Equal(t, "bu", uc.Name)
}

func TestGenerateConfig_InteractiveHonorsAccount(t *testing.T) {
	ts := NewTestStore(t, "operator")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "au")
	ts.AddAccount(t, "B")
	ts.AddUser(t, "B", "bu")

	t.Log(os.Args[0])

	inputs := []interface{}{0}
	stdout, err := ExecuteInteractiveCmd(createGenerateCredsCmd(), inputs)
	require.NoError(t, err)
	userToken, err := jwt.ParseDecoratedJWT([]byte(stdout.Out))
	require.NoError(t, err)

	uc, err := jwt.DecodeUserClaims(userToken)
	require.NoError(t, err)
	require.Equal(t, "au", uc.Name)
}
