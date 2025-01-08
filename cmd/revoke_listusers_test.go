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
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"
)

func TestRevokeListUsers(t *testing.T) {
	ts := NewTestStore(t, "revoke_clear_user")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "one")
	ts.AddUser(t, "A", "two")
	ts.AddUser(t, "A", "three")

	_, err := ExecuteCmd(createRevokeUserCmd(), []string{"--name", "one", "--at", "1001"}...)
	require.NoError(t, err)

	_, err = ExecuteCmd(createRevokeUserCmd(), []string{"--name", "two", "--at", "2001"}...)
	require.NoError(t, err)

	out, err := ExecuteCmd(createRevokeListUsersCmd())
	require.NoError(t, err)

	u, err := ts.Store.ReadUserClaim("A", "one")
	require.NoError(t, err)
	require.True(t, strings.Contains(out.Out, u.Subject))
	require.True(t, strings.Contains(out.Out, time.Unix(1001, 0).Format(time.RFC1123)))

	u, err = ts.Store.ReadUserClaim("A", "two")
	require.NoError(t, err)
	require.True(t, strings.Contains(out.Out, u.Subject))
	require.True(t, strings.Contains(out.Out, time.Unix(2001, 0).Format(time.RFC1123)))
}

func TestRevokeListUsersNoAccount(t *testing.T) {
	ts := NewTestStore(t, "revoke_clear_user")
	defer ts.Done(t)
	_, err := ExecuteInteractiveCmd(createRevokeListUsersCmd(), []interface{}{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no accounts defined")
}

func TestRevokeListUsersNoRevocations(t *testing.T) {
	ts := NewTestStore(t, "revoke_clear_user")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	_, err := ExecuteCmd(createRevokeListUsersCmd(), []string{}...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not have revoked users")
}

func TestRevokeListUsersAllUsers(t *testing.T) {
	ts := NewTestStore(t, "revoke_clear_user")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	_, err := ExecuteCmd(createRevokeUserCmd(), "-u", "*")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.Revocations, jwt.All)

	out, err := ExecuteCmd(createRevokeListUsersCmd())
	require.NoError(t, err)
	require.Contains(t, out.Out, "* [All Users]")
}
