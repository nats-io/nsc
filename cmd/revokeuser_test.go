/*
 * Copyright 2018 The NATS Authors
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
	"time"

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
	require.True(t, ac.IsRevokedAt(u.Subject, time.Unix(0, 0)))

	_, _, err = ExecuteCmd(createRevokeUserCmd(), "--name", "two")
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Revocations, 2)

	u, err = ts.Store.ReadUserClaim("A", "two")
	require.NoError(t, err)
	require.True(t, ac.IsRevokedAt(u.Subject, time.Unix(0, 0)))

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
	require.True(t, ac.IsRevokedAt(u.Subject, time.Unix(999, 0)))
	require.False(t, ac.IsRevokedAt(u.Subject, time.Unix(1001, 0)))

	_, _, err = ExecuteCmd(createRevokeUserCmd(), "--name", "two", "--at", "2000")
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Revocations, 2)

	u, err = ts.Store.ReadUserClaim("A", "two")
	require.NoError(t, err)
	require.True(t, ac.IsRevokedAt(u.Subject, time.Unix(1999, 0)))
	require.False(t, ac.IsRevokedAt(u.Subject, time.Unix(2001, 0)))
}

func Test_RevokeUserAccountNameRequired(t *testing.T) {
	ts := NewTestStoreWithOperator(t, "test", nil)
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

func TestRevokeUserInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "one")
	ts.AddUser(t, "A", "two")
	ts.AddAccount(t, "B")
	ts.AddUser(t, "B", "one")
	ts.AddUser(t, "B", "two")

	input := []interface{}{0, 0, "0"}
	cmd := createRevokeUserCmd()
	HoistRootFlags(cmd)
	_, _, err := ExecuteInteractiveCmd(cmd, input, "-i")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.Revocations, 1)

	u, err := ts.Store.ReadUserClaim("A", "one")
	require.NoError(t, err)
	require.True(t, ac.IsRevokedAt(u.Subject, time.Unix(0, 0)))
	require.False(t, ac.IsRevokedAt(u.Subject, time.Now().Add(1*time.Hour)))
}
