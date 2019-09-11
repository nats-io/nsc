/*
 * Copyright 2018-2019 The NATS Authors
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

func Test_AddUser(t *testing.T) {
	ts := NewTestStore(t, "add_server")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(CreateAddAccountCmd(), "--name", "c")
	require.NoError(t, err, "cluster creation")

	_, bar, _ := CreateUserKey(t)
	_, badBar, _ := CreateAccountKey(t)

	tests := CmdTests{
		{CreateAddUserCmd(), []string{"add", "user"}, nil, []string{"user name is required"}, true},
		{CreateAddUserCmd(), []string{"add", "user", "--name", "foo"}, nil, []string{"Generated user key", "added user"}, false},
		{CreateAddUserCmd(), []string{"add", "user", "--name", "foo"}, nil, []string{"the user \"foo\" already exists"}, true},
		{CreateAddUserCmd(), []string{"add", "user", "--name", "foo"}, nil, []string{"the user \"foo\" already exists"}, true},
		{CreateAddUserCmd(), []string{"add", "user", "--name", "*"}, nil, []string{"Generated user key", "added user"}, false},
		{CreateAddUserCmd(), []string{"add", "user", "--name", "*"}, nil, []string{"Generated user key", "added user"}, false}, // should make a new name
		{CreateAddUserCmd(), []string{"add", "user", "--name", "bar", "--public-key", bar}, nil, nil, false},
		{CreateAddUserCmd(), []string{"add", "user", "--name", "badbar", "--public-key", badBar}, nil, []string{"invalid user key"}, true},
		{CreateAddUserCmd(), []string{"add", "user", "--name", "badexp", "--expiry", "30d"}, nil, nil, false},
	}

	tests.Run(t, "root", "add")
}

func Test_AddUserNoStore(t *testing.T) {
	// reset the store
	ngsStore = nil
	ForceStoreRoot(t, "")
	_, _, err := ExecuteCmd(CreateAddUserCmd())
	require.Equal(t, "no stores available", err.Error())
}

func Test_AddUserOutput(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(CreateAddAccountCmd(), "--name", "A")
	require.NoError(t, err, "account creation")

	_, _, err = ExecuteCmd(CreateAddUserCmd(), "--name", "U", "--start", "2018-01-01", "--expiry", "2050-01-01")
	require.NoError(t, err)
	validateAddUserClaims(t, ts)
}

func Test_AddUserInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(CreateAddAccountCmd(), "--name", "A")
	require.NoError(t, err, "account creation")

	inputs := []interface{}{"U", true, false, "2018-01-01", "2050-01-01", 0}

	cmd := CreateAddUserCmd()
	HoistRootFlags(cmd)
	_, _, err = ExecuteInteractiveCmd(cmd, inputs)
	require.NoError(t, err)
	validateAddUserClaims(t, ts)

	up, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Nil(t, up.Resp)
}

func validateAddUserClaims(t *testing.T, ts *TestStore) {
	skp := ts.GetUserKey(t, "A", "U")
	_, err := skp.Seed()
	require.NoError(t, err, "stored key should be a seed")

	sc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err, "reading user claim")

	pub, err := skp.PublicKey()
	require.NoError(t, err)
	require.Equal(t, sc.Subject, pub, "public key is subject")

	okp := ts.GetAccountKey(t, "A")

	oppub, err := okp.PublicKey()
	require.NoError(t, err, "getting public key for account")
	require.Equal(t, sc.Issuer, oppub, "account signed it")

	start, err := ParseExpiry("2018-01-01")
	require.NoError(t, err)
	require.Equal(t, start, sc.NotBefore)

	expire, err := ParseExpiry("2050-01-01")
	require.NoError(t, err)
	require.Equal(t, expire, sc.Expires)
}

func Test_AddUserManagedStore(t *testing.T) {
	as, m := RunTestAccountServer(t)
	defer as.Close()

	ts := NewTestStoreWithOperatorJWT(t, string(m["operator"]))
	defer ts.Done(t)

	_, _, err := ExecuteCmd(CreateAddAccountCmd(), "--name", "A", "--start", "2018-01-01", "--expiry", "2050-01-01")
	require.NoError(t, err)

	_, _, err = ExecuteCmd(CreateAddUserCmd(), "--name", "U", "--start", "2018-01-01", "--expiry", "2050-01-01")
	require.NoError(t, err)

	validateAddUserClaims(t, ts)
}

func Test_AddUser_Account(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(CreateAddAccountCmd(), "--name", "A", "--start", "2018-01-01", "--expiry", "2050-01-01")
	require.NoError(t, err)

	_, _, err = ExecuteCmd(CreateAddAccountCmd(), "--name", "B", "--start", "2018-01-01", "--expiry", "2050-01-01")
	require.NoError(t, err)

	config := GetConfig()
	err = config.SetAccount("A")
	require.NoError(t, err)

	_, _, err = ExecuteCmd(CreateAddUserCmd(), "--name", "bb", "--account", "B")
	require.NoError(t, err)

	u, err := ts.Store.ReadUserClaim("B", "bb")
	require.NoError(t, err)
	require.NotNil(t, u)
}

func Test_AddUser_WithSK(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(CreateAddAccountCmd(), "--name", "A")
	require.NoError(t, err)

	config := GetConfig()
	err = config.SetAccount("A")
	require.NoError(t, err)

	sk, pk, _ := CreateAccountKey(t)
	_, _, err = ExecuteCmd(createEditAccount(), "--sk", pk)
	require.NoError(t, err)

	_, _, err = ExecuteCmd(HoistRootFlags(CreateAddUserCmd()), "--name", "bb", "--account", "A", "-K", string(sk))
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)

	u, err := ts.Store.ReadUserClaim("A", "bb")
	require.NoError(t, err)
	require.NotNil(t, u)
	require.Equal(t, u.Issuer, pk)

	require.True(t, ac.DidSign(u))
}

func Test_AddUser_InteractiveResp(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	_, _, err := ExecuteCmd(CreateAddAccountCmd(), "--name", "A")
	require.NoError(t, err, "account creation")

	inputs := []interface{}{"U", true, true, "100", "1000ms", "2018-01-01", "2050-01-01", 0}

	cmd := CreateAddUserCmd()
	HoistRootFlags(cmd)
	_, _, err = ExecuteInteractiveCmd(cmd, inputs)
	require.NoError(t, err)
	validateAddUserClaims(t, ts)

	up, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.NotNil(t, up.Resp)
	require.Equal(t, 100, up.Resp.MaxMsgs)
	require.Equal(t, time.Millisecond*1000, up.Resp.Expires)
}
