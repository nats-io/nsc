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
	"strconv"
	"testing"
	"time"

	"github.com/nats-io/jwt"

	"github.com/stretchr/testify/require"
)

func TestRevokeUser(t *testing.T) {
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
	require.True(t, ac.IsClaimRevoked(u))

	_, _, err = ExecuteCmd(createRevokeUserCmd(), "--name", "two")
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Revocations, 2)

	u, err = ts.Store.ReadUserClaim("A", "two")
	require.NoError(t, err)
	require.True(t, ac.IsClaimRevoked(u))

	// Double doesn't do anything
	_, _, err = ExecuteCmd(createRevokeUserCmd(), "--name", "two")
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Revocations, 2)
}

func TestRevokeUserAt(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "one")
	ts.AddUser(t, "A", "two")
	ts.AddUser(t, "A", "three")

	_, _, err := ExecuteCmd(createRevokeUserCmd(), "--name", "one", "--at", "1000")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Revocations, 1)

	u, err := ts.Store.ReadUserClaim("A", "one")
	require.NoError(t, err)
	require.False(t, ac.IsClaimRevoked(u))
	_, ok := ac.Revocations[u.Subject]
	require.True(t, ok)

	_, _, err = ExecuteCmd(createRevokeUserCmd(), "--name", "two", "--at", strconv.Itoa(int(time.Now().Unix())))
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Revocations, 2)

	u, err = ts.Store.ReadUserClaim("A", "two")
	require.NoError(t, err)
	require.True(t, ac.IsClaimRevoked(u))
	_, ok = ac.Revocations[u.Subject]
	require.True(t, ok)
}

func Test_RevokeUserAccountNameRequired(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "one")

	ts.AddAccount(t, "B")
	ts.AddUser(t, "B", "one")

	_, _, err := ExecuteCmd(createRevokeUserCmd(), "--name", "one")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	require.Len(t, ac.Revocations, 1)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Revocations, 0)
}

const keyToRevoke = "UCLMBZ5CBDRDG2TAYOJK23U7IGKPTTW7DTWNOP4TUW4PAB3GRUSKXG3N"

func TestRevokeUserInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "one")
	ts.AddUser(t, "A", "two")
	ts.AddAccount(t, "B")
	ts.AddUser(t, "B", "one")
	ts.AddUser(t, "B", "two")

	input := []interface{}{0, true, 0, "0"}
	cmd := createRevokeUserCmd()
	HoistRootFlags(cmd)
	_, _, err := ExecuteInteractiveCmd(cmd, input, "-i")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Revocations, 1)

	u, err := ts.Store.ReadUserClaim("A", "one")
	require.NoError(t, err)
	require.True(t, ac.IsClaimRevoked(u))

	cmd = createRevokeUserCmd()
	HoistRootFlags(cmd)
	input = []interface{}{0, false, keyToRevoke, "0"}
	_, _, err = ExecuteInteractiveCmd(cmd, input, "-i")
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.True(t, ac.Revocations.IsRevoked(keyToRevoke, time.Unix(0, 0)))
	require.False(t, ac.Revocations.IsRevoked(keyToRevoke, time.Now().Add(1*time.Hour)))
	require.Len(t, ac.Revocations, 2)
}

func TestRevokeUserByNkey(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "one")
	ts.AddUser(t, "A", "two")

	u, err := ts.Store.ReadUserClaim("A", "one")
	require.NoError(t, err)

	cmd := createRevokeUserCmd()
	HoistRootFlags(cmd)
	_, _, err = ExecuteCmd(cmd, "-u", u.Subject)
	require.NoError(t, err)
	_, _, err = ExecuteCmd(cmd, "-u", keyToRevoke)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Revocations, 2)
	require.True(t, ac.Revocations.IsRevoked(u.Subject, time.Unix(0, 0)))
	require.True(t, ac.Revocations.IsRevoked(keyToRevoke, time.Unix(0, 0)))

	// make sure one is expired
	u, err = ts.Store.ReadUserClaim("A", "one")
	require.NoError(t, err)
	require.True(t, ac.IsClaimRevoked(u))
	// make sure two is not expired
	u, err = ts.Store.ReadUserClaim("A", "two")
	require.NoError(t, err)
	require.False(t, ac.IsClaimRevoked(u))
}

func TestRevokeUserNameKey(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	_, _, err := ExecuteCmd(createRevokeUserCmd(), "--name", "a", "--user-public-key", "UAUGJSHSTZY4ESHTL32CYYQNGT6MHXDQY6APMFMVRXWZN76RHE2IRN5O")
	require.Error(t, err)
	require.Contains(t, err.Error(), "user and user-public-key are mutually exclusive")
}

func TestRevokeUserNameNotFound(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")
	_, _, err := ExecuteCmd(createRevokeUserCmd(), "--name", "a")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")

	_, _, err = ExecuteCmd(createRevokeUserCmd(), "--name", "U")
	require.NoError(t, err)
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	upk := ts.GetUserPublicKey(t, "A", "U")
	require.NotEmpty(t, upk)
	require.Contains(t, ac.Revocations, upk)
}

func TestRevokeDefaultUser(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")
	_, _, err := ExecuteCmd(createRevokeUserCmd())
	require.NoError(t, err)

	upk := ts.GetUserPublicKey(t, "A", "U")
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	_, ok := ac.Revocations[upk]
	require.True(t, ok)
}

func TestRevokeUserRequired(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")
	ts.AddUser(t, "A", "Y")
	_, _, err := ExecuteCmd(createRevokeUserCmd())
	require.Error(t, err)
	require.Contains(t, err.Error(), "no default user available")
}

func TestRevokeAllUsers(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	_, _, err := ExecuteCmd(createRevokeUserCmd(), "-u", "*")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.Revocations, jwt.All)
}

func TestRevokeBadUnixTime(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	_, _, err := ExecuteCmd(createRevokeUserCmd(), "-u", "*", "--at", "hello")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid argument")
}

func TestRevokeRFC3339Time(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	at := time.Now()
	_, _, err := ExecuteCmd(createRevokeUserCmd(), "-u", "*", "--at", at.Format(time.RFC3339))
	require.NoError(t, err)

	c, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.True(t, c.Revocations.IsRevoked("foo", at))
	require.False(t, c.Revocations.IsRevoked("foo", at.Add(time.Second)))
}

func TestRevokeBadUnixTimeInteractive(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	input := []interface{}{"*", "hello"}
	_, _, err := ExecuteInteractiveCmd(createRevokeUserCmd(), input)
	require.Error(t, err)
	require.Contains(t, err.Error(), `provided value "hello" is not`)
}
