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

	"github.com/stretchr/testify/require"
)

func Test_AddUser(t *testing.T) {
	ts := NewTestStore(t, "add_server")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(createAddAccountCmd(), "--name", "c")
	require.NoError(t, err, "cluster creation")

	_, bar, _ := CreateUserKey(t)
	_, badBar, _ := CreateAccountKey(t)

	tests := CmdTests{
		{createAddUserCmd(), []string{"add", "user"}, nil, []string{"user name is required"}, true},
		{createAddUserCmd(), []string{"add", "user", "--name", "foo"}, nil, []string{"Generated user key", "added user"}, false},
		{createAddUserCmd(), []string{"add", "user", "--name", "foo"}, nil, []string{"the user \"foo\" already exists"}, true},
		{createAddUserCmd(), []string{"add", "user", "--name", "foo"}, nil, []string{"the user \"foo\" already exists"}, true},
		{createAddUserCmd(), []string{"add", "user", "--name", "bar", "--public-key", bar}, nil, nil, false},
		{createAddUserCmd(), []string{"add", "user", "--name", "badbar", "--public-key", badBar}, nil, []string{"invalid user key"}, true},
		{createAddUserCmd(), []string{"add", "user", "--name", "badexp", "--expiry", "2018-01-01"}, nil, []string{"expiry \"2018-01-01\" is in the past"}, true},
		{createAddUserCmd(), []string{"add", "user", "--name", "badexp", "--expiry", "30d"}, nil, nil, false},
	}

	tests.Run(t, "root", "add")
}

func Test_AddUserNoStore(t *testing.T) {
	// reset the store
	ngsStore = nil
	_, _, err := ExecuteCmd(createAddUserCmd())
	require.Equal(t, "no store directory found", err.Error())
}

func Test_AddUserrOutput(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(createAddAccountCmd(), "--name", "c")
	require.NoError(t, err, "account creation")

	_, _, err = ExecuteCmd(createAddUserCmd(), "--name", "a", "--start", "2018-01-01", "--expiry", "2050-01-01")
	require.NoError(t, err)

	skp, err := ts.KeyStore.GetUserKey("operator", "c", "a")
	_, err = skp.Seed()
	require.NoError(t, err, "stored key should be a seed")

	sc, err := ts.Store.ReadUserClaim("c", "a")
	require.NoError(t, err, "reading user claim")

	pub, err := skp.PublicKey()
	require.Equal(t, sc.Subject, string(pub), "public key is subject")

	okp, err := ts.KeyStore.GetAccountKey("operator", "c")
	require.NoError(t, err)

	oppub, err := okp.PublicKey()
	require.NoError(t, err, "getting public key for account")
	require.Equal(t, sc.Issuer, string(oppub), "account signed it")

	start, err := ParseExpiry("2018-01-01")
	require.NoError(t, err)
	require.Equal(t, start, sc.NotBefore)

	expire, err := ParseExpiry("2050-01-01")
	require.NoError(t, err)
	require.Equal(t, expire, sc.Expires)
}
