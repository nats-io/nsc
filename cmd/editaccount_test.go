/*
 *
 *  * Copyright 2018-2021 The NATS Authors
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  * http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package cmd

import (
	"testing"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/stretchr/testify/require"
)

func Test_EditAccount(t *testing.T) {
	ts := NewTestStore(t, "edit account")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	tests := CmdTests{
		{createEditAccount(), []string{"edit", "account"}, nil, []string{"specify an edit option"}, true},
		{createEditAccount(), []string{"edit", "account", "--info-url", "http://foo/bar"}, nil, []string{"changed info url to"}, false},
		{createEditAccount(), []string{"edit", "account", "--description", "my account is about this"}, nil, []string{"changed description to"}, false},
		{createEditAccount(), []string{"edit", "account", "--tag", "A", "--name", "A"}, nil, []string{"edited account \"A\""}, false},
	}

	tests.Run(t, "root", "edit")
}

func Test_EditAccountRequired(t *testing.T) {
	ts := NewTestStore(t, "edit account")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")
	require.NoError(t, GetConfig().SetAccount(""))
	_, _, err := ExecuteCmd(createEditAccount(), "--tag", "A")
	require.Error(t, err)
	require.Contains(t, "an account is required", err.Error())
}

func Test_EditAccount_Tag(t *testing.T) {
	ts := NewTestStore(t, "edit account")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, _, err := ExecuteCmd(createEditAccount(), "--tag", "A,B,C")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)

	require.Len(t, ac.Tags, 3)
	require.ElementsMatch(t, ac.Tags, []string{"a", "b", "c"})
}

func Test_EditAccount_RmTag(t *testing.T) {
	ts := NewTestStore(t, "edit account")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, _, err := ExecuteCmd(createEditAccount(), "--tag", "A,B,C")
	require.NoError(t, err)

	_, _, err = ExecuteCmd(createEditAccount(), "--rm-tag", "A,B")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)

	require.Len(t, ac.Tags, 1)
	require.ElementsMatch(t, ac.Tags, []string{"c"})
}

func Test_EditAccount_Times(t *testing.T) {
	ts := NewTestStore(t, "edit account")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	_, _, err := ExecuteCmd(createEditAccount(), "--start", "2018-01-01", "--expiry", "2050-01-01")
	require.NoError(t, err)

	start, err := ParseExpiry("2018-01-01")
	require.NoError(t, err)

	expiry, err := ParseExpiry("2050-01-01")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, start, ac.NotBefore)
	require.Equal(t, expiry, ac.Expires)
}

func Test_EditAccountLimits(t *testing.T) {
	ts := NewTestStore(t, "edit account")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, _, err := ExecuteCmd(createEditAccount(), "--conns", "5", "--data", "10mib", "--exports", "15",
		"--imports", "20", "--payload", "1Kib", "--subscriptions", "30", "--leaf-conns", "31",
		"--streams", "5", "--consumer", "6", "--disk-storage", "7", "--mem-storage", "8")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, int64(5), ac.Limits.Conn)
	require.Equal(t, int64(31), ac.Limits.LeafNodeConn)
	require.Equal(t, int64(1024*1024*10), ac.Limits.Data)
	require.Equal(t, int64(15), ac.Limits.Exports)
	require.Equal(t, int64(20), ac.Limits.Imports)
	require.Equal(t, int64(1024), ac.Limits.Payload)
	require.Equal(t, int64(30), ac.Limits.Subs)
	require.Equal(t, int64(5), ac.Limits.Streams)
	require.Equal(t, int64(6), ac.Limits.Consumer)
	require.Equal(t, int64(7), ac.Limits.DiskStorage)
	require.Equal(t, int64(8), ac.Limits.MemoryStorage)
}

func Test_EditAccountSigningKeys(t *testing.T) {
	ts := NewTestStore(t, "edit account")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, pk, _ := CreateAccountKey(t)
	_, pk2, _ := CreateAccountKey(t)

	_, _, err := ExecuteCmd(createEditAccount(), "--sk", pk, "--sk", pk2)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.SigningKeys, pk)
	require.Contains(t, ac.SigningKeys, pk2)

	_, _, err = ExecuteCmd(createEditAccount(), "--rm-sk", pk)
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotContains(t, ac.SigningKeys, pk)
}

func Test_EditAccount_Pubs(t *testing.T) {
	ts := NewTestStore(t, "edit user")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	_, _, err := ExecuteCmd(createEditAccount(), "--allow-pub", "a,b", "--allow-pubsub", "c", "--deny-pub", "foo", "--deny-pubsub", "bar")
	require.NoError(t, err)

	cc, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, cc)
	require.ElementsMatch(t, cc.DefaultPermissions.Pub.Allow, []string{"a", "b", "c"})
	require.ElementsMatch(t, cc.DefaultPermissions.Sub.Allow, []string{"c"})
	require.ElementsMatch(t, cc.DefaultPermissions.Pub.Deny, []string{"foo", "bar"})
	require.ElementsMatch(t, cc.DefaultPermissions.Sub.Deny, []string{"bar"})

	_, _, err = ExecuteCmd(createEditAccount(), "--rm", "c,bar")
	require.NoError(t, err)
	cc, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, cc)

	require.ElementsMatch(t, cc.DefaultPermissions.Pub.Allow, []string{"a", "b"})
	require.Len(t, cc.DefaultPermissions.Sub.Allow, 0)
	require.ElementsMatch(t, cc.DefaultPermissions.Pub.Deny, []string{"foo"})
	require.Len(t, cc.DefaultPermissions.Sub.Deny, 0)
}

func Test_EditAccountResponsePermissions(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	_, _, err := ExecuteCmd(createEditAccount(), "--max-responses", "1000", "--response-ttl", "4ms")
	require.NoError(t, err)

	uc, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, uc.DefaultPermissions.Resp)
	require.Equal(t, 1000, uc.DefaultPermissions.Resp.MaxMsgs)
	d, _ := time.ParseDuration("4ms")
	require.Equal(t, d, uc.DefaultPermissions.Resp.Expires)

	_, _, err = ExecuteCmd(createEditAccount(), "--rm-response-perms")
	require.NoError(t, err)

	uc, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Nil(t, uc.DefaultPermissions.Resp)
}

func Test_EditAccountSk(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	sk, err := nkeys.CreateOperator()
	require.NoError(t, err)
	_, err = ts.KeyStore.Store(sk)
	require.NoError(t, err)
	pSk, err := sk.PublicKey()
	require.NoError(t, err)

	_, _, err = ExecuteCmd(createEditOperatorCmd(), "--sk", pSk)
	require.NoError(t, err)

	ts.AddAccountWithSigner(t, "A", sk)
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, ac.Issuer, pSk)

	_, _, err = ExecuteCmd(createEditAccount(), "--tag", "foo")
	require.NoError(t, err)
	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Equal(t, ac.Issuer, pSk)
}

func Test_EditOperatorDisallowBearerToken(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	_, _, err := ExecuteCmd(createEditUserCmd(), "--name", "U", "--bearer")
	require.NoError(t, err)

	_, _, err = ExecuteCmd(createEditAccount(), "--name", "A", "--disallow-bearer")
	require.Error(t, err)
	require.Equal(t, err.Error(), `user "U" in account "A" uses bearer token (needs to be deleted/changed first)`)

	// delete offending user
	_, _, err = ExecuteCmd(createDeleteUserCmd(), "--account", "A", "--name", "U")
	require.NoError(t, err)
	// set option
	_, _, err = ExecuteCmd(createEditAccount(), "--name", "A", "--disallow-bearer")
	require.NoError(t, err)
	// test user creation
	_, _, err = ExecuteCmd(CreateAddUserCmd(), "--account", "A", "--name", "U", "--bearer")
	require.Error(t, err)
	require.Equal(t, err.Error(), `account "A" forbids the use of bearer token`)
	_, _, err = ExecuteCmd(CreateAddUserCmd(), "--account", "A", "--name", "U")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(createEditUserCmd(), "--account", "A", "--name", "U", "--bearer")
	require.Error(t, err)
	require.Equal(t, err.Error(), "account disallows bearer token")
}
