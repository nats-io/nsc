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
	"testing"

	cli "github.com/nats-io/cliprompts/v2"

	"github.com/stretchr/testify/require"
)

func TestRevokeClearUser(t *testing.T) {
	ts := NewTestStore(t, "revoke_clear_user")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "one")
	ts.AddUser(t, "A", "two")
	ts.AddUser(t, "A", "three")

	_, _, err := ExecuteCmd(createRevokeUserCmd(), "--name", "one")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Revocations, 1)

	u, err := ts.Store.ReadUserClaim("A", "one")
	require.NoError(t, err)
	require.Contains(t, ac.Revocations, u.Subject)

	_, _, err = ExecuteCmd(createClearRevokeUserCmd(), "--name", "one")
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Revocations, 0)

	// error if not revoked
	_, _, err = ExecuteCmd(createClearRevokeUserCmd(), "--name", "one")
	require.Error(t, err)
}

func TestRevokeClearUserInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "one")
	ts.AddUser(t, "A", "two")
	ts.AddAccount(t, "B")
	ts.AddUser(t, "B", "one")
	ts.AddUser(t, "B", "two")

	_, _, err := ExecuteCmd(createRevokeUserCmd(), "--name", "one", "--account", "A")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Revocations, 1)

	u, err := ts.Store.ReadUserClaim("A", "one")
	require.NoError(t, err)
	require.Contains(t, ac.Revocations, u.Subject)

	// first account and first user
	input := []interface{}{0, 0}
	cmd := createClearRevokeUserCmd()
	HoistRootFlags(cmd)
	cli.LogFn = t.Log
	_, _, err = ExecuteInteractiveCmd(cmd, input, "-i")
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Revocations, 0)
}

func TestClearRevokeUserUserAndKey(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	_, _, err := ExecuteCmd(createClearRevokeUserCmd(), "--name", "a", "--user-public-key", "UAUGJSHSTZY4ESHTL32CYYQNGT6MHXDQY6APMFMVRXWZN76RHE2IRN5O")
	require.Error(t, err)
	require.Contains(t, err.Error(), "user and user-public-key are mutually exclusive")
}

func TestClearRevokeUserNotFound(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")
	_, _, err := ExecuteCmd(createClearRevokeUserCmd(), "--name", "uu")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

func TestClearRevokeDefaultUser(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")
	_, _, err := ExecuteCmd(createRevokeUserCmd())
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createClearRevokeUserCmd())
	require.NoError(t, err)
}

func TestClearRevokeRevocationNotFound(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")
	_, _, err := ExecuteCmd(createRevokeUserCmd())
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createClearRevokeUserCmd(), "-u", "*")
	require.Error(t, err)
	require.Contains(t, err.Error(), "user with public key * is not revoked")
}

func TestClearRevokeAllUsers(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	_, _, err := ExecuteCmd(createRevokeUserCmd(), "-u", "*")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createClearRevokeUserCmd(), "-u", "*")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Empty(t, ac.Revocations)
}
