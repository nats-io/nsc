// Copyright 2018-2025 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"github.com/nats-io/cliprompts/v2"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_AddUser(t *testing.T) {
	ts := NewTestStore(t, "add_server")
	defer ts.Done(t)

	_, err := ExecuteCmd(CreateAddAccountCmd(), []string{"--name", "c"}...)
	require.NoError(t, err)

	_, bar, _ := CreateUserKey(t)
	_, badBar, _ := CreateAccountKey(t)

	tests := CmdTests{
		{CreateAddUserCmd(), []string{"add", "user"}, nil, []string{"user name is required"}, true},
		{CreateAddUserCmd(), []string{"add", "user", "--name", "foo"}, []string{"generated and stored user key", "added user"}, nil, false},
		{CreateAddUserCmd(), []string{"add", "user", "--name", "foo"}, nil, []string{"the user \"foo\" already exists"}, true},
		{CreateAddUserCmd(), []string{"add", "user", "--name", "foo"}, nil, []string{"the user \"foo\" already exists"}, true},
		{CreateAddUserCmd(), []string{"add", "user", "--name", "*"}, []string{"generated and stored user key", "added user"}, nil, false},
		{CreateAddUserCmd(), []string{"add", "user", "--name", "*"}, []string{"generated and stored user key", "added user"}, nil, false}, // should make a new name
		{CreateAddUserCmd(), []string{"add", "user", "--name", "bar", "--public-key", bar}, nil, nil, false},
		{CreateAddUserCmd(), []string{"add", "user", "--name", "badbar", "--public-key", badBar}, nil, []string{"invalid user key"}, true},
		{CreateAddUserCmd(), []string{"add", "user", "--name", "badexp", "--expiry", "30d"}, nil, nil, false},
		{CreateAddUserCmd(), []string{"add", "user", "--name", "usra", "--deny-sub", "foo queue"}, []string{"added user"}, nil, false},
		{CreateAddUserCmd(), []string{"add", "user", "--name", "usrb", "--allow-sub", "foo queue"}, []string{"added user"}, nil, false},
		{CreateAddUserCmd(), []string{"add", "user", "--name", "usrc", "--deny-pub", "foo queue"}, nil, []string{"contains illegal space"}, true},
		{CreateAddUserCmd(), []string{"add", "user", "--name", "usrd", "--allow-pub", "foo queue"}, nil, []string{"contains illegal space"}, true},
		{CreateAddUserCmd(), []string{"add", "user", "--name", "usre", "--deny-pubsub", "foo queue"}, nil, []string{"contains illegal space"}, true},
		{CreateAddUserCmd(), []string{"add", "user", "--name", "usrf", "--allow-pubsub", "foo queue"}, nil, []string{"contains illegal space"}, true},
		{CreateAddUserCmd(), []string{"add", "user", "--name", "usrg", "--deny-sub", "foo queue doo"}, nil, []string{"can at most contain one space"}, true},
		{CreateAddUserCmd(), []string{"add", "user", "--name", "usrh", "--allow-sub", "foo queue doo"}, nil, []string{"can at most contain one space"}, true},
	}

	tests.Run(t, "root", "add")
}

func Test_AddUserNoStore(t *testing.T) {
	// reset the store
	require.NoError(t, ForceStoreRoot(t, ""))
	_, err := ExecuteCmd(CreateAddUserCmd(), []string{}...)
	require.Error(t, err)
	require.Equal(t, "no stores available", err.Error())
}

func Test_AddUserOutput(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	_, err := ExecuteCmd(CreateAddAccountCmd(), []string{"--name", "A"}...)
	require.NoError(t, err, "account creation")

	_, err = ExecuteCmd(CreateAddUserCmd(), []string{"--name", "U", "--start", "2018-01-01", "--expiry", "2050-01-01"}...)
	require.NoError(t, err)
	validateAddUserClaims(t, ts)
}

func Test_AddUserInteractive(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	_, err := ExecuteCmd(CreateAddAccountCmd(), []string{"--name", "A"}...)
	require.NoError(t, err, "account creation")

	inputs := []interface{}{"U", true, "2018-01-01", "2050-01-01", 0}

	cmd := CreateAddUserCmd()
	HoistRootFlags(cmd)
	_, err = ExecuteInteractiveCmd(cmd, inputs)
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

	_, err := ExecuteCmd(CreateAddAccountCmd(), []string{"--name", "A", "--start", "2018-01-01", "--expiry", "2050-01-01"}...)
	require.NoError(t, err)

	_, err = ExecuteCmd(CreateAddUserCmd(), []string{"--name", "U", "--start", "2018-01-01", "--expiry", "2050-01-01"}...)
	require.NoError(t, err)

	validateAddUserClaims(t, ts)
}

func Test_AddUser_Account(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	config := GetConfig()
	err := config.SetAccount("A")
	require.NoError(t, err)

	_, err = ExecuteCmd(CreateAddUserCmd(), []string{"--name", "bb", "--account", "B"}...)
	require.NoError(t, err)

	u, err := ts.Store.ReadUserClaim("B", "bb")
	require.NoError(t, err)
	require.NotNil(t, u)
}

func Test_AddUser_WithSK(t *testing.T) {
	ts := NewTestStore(t, "test")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	sk, pk, _ := CreateAccountKey(t)
	_, err := ExecuteCmd(createEditAccount(), []string{"--sk", pk}...)
	require.NoError(t, err)

	_, err = ExecuteCmd(HoistRootFlags(CreateAddUserCmd()), []string{"--name", "bb", "--account", "A", "-K", string(sk)}...)
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

	_, err := ExecuteCmd(CreateAddAccountCmd(), []string{"--name", "A"}...)
	require.NoError(t, err, "account creation")

	inputs := []interface{}{"U", true, "2018-01-01", "2050-01-01"}
	cliprompts.LogFn = t.Log
	cmd := CreateAddUserCmd()
	HoistRootFlags(cmd)
	_, err = ExecuteInteractiveCmd(cmd, inputs)
	require.NoError(t, err)
	validateAddUserClaims(t, ts)

	up, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Equal(t, time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC).Unix(), up.NotBefore)
	require.Equal(t, time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC).Unix(), up.Expires)
}

func Test_AddUserNameArg(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	_, err := ExecuteCmd(HoistRootFlags(CreateAddUserCmd()), []string{"U"}...)
	require.NoError(t, err)

	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Equal(t, "U", uc.Name)
}

func Test_AddUserWithResponsePerms(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	_, err := ExecuteCmd(CreateAddUserCmd(), []string{"U", "--max-responses", "100", "--response-ttl", "2ms"}...)
	require.NoError(t, err)

	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.NotNil(t, uc.Resp)
	require.Equal(t, 100, uc.Resp.MaxMsgs)
	d, _ := time.ParseDuration("2ms")
	require.Equal(t, d, uc.Resp.Expires)
}

func Test_AddUserWithResponsePerms2(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	_, err := ExecuteCmd(CreateAddUserCmd(), []string{"U", "--allow-pub-response", "--response-ttl", "2ms"}...)
	require.NoError(t, err)

	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.NotNil(t, uc.Resp)
	require.Equal(t, 1, uc.Resp.MaxMsgs)
	d, _ := time.ParseDuration("2ms")
	require.Equal(t, d, uc.Resp.Expires)
}

func Test_AddUserWithInteractiveAccountCtx(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	// adding to user bb to B
	inputs := []interface{}{1, "bb", true, "0", "0", 0}
	cmd := CreateAddUserCmd()
	HoistRootFlags(cmd)
	_, err := ExecuteInteractiveCmd(cmd, inputs)
	require.NoError(t, err)

	bpk := ts.GetAccountPublicKey(t, "B")
	uc, err := ts.Store.ReadUserClaim("B", "bb")
	require.NoError(t, err)
	require.Equal(t, bpk, uc.Issuer)
	require.Empty(t, uc.IssuerAccount)

	// adding to user aa to A
	inputs = []interface{}{0, "aa", true, "0", "0", 0}
	_, err = ExecuteInteractiveCmd(cmd, inputs)
	require.NoError(t, err)
	apk := ts.GetAccountPublicKey(t, "A")

	uc, err = ts.Store.ReadUserClaim("A", "aa")
	require.NoError(t, err)
	require.Equal(t, apk, uc.Issuer)
	require.Empty(t, uc.IssuerAccount)
}

func Test_AddUserWithInteractiveCustomKey(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	kp, err := nkeys.CreateUser()
	require.NoError(t, err)
	sk, err := kp.Seed()
	require.NoError(t, err)
	pk, err := kp.PublicKey()
	require.NoError(t, err)

	inputs := []interface{}{"aa", false, string(sk), "0", "0"}
	cmd := CreateAddUserCmd()
	HoistRootFlags(cmd)
	_, err = ExecuteInteractiveCmd(cmd, inputs)
	require.NoError(t, err)

	uc, err := ts.Store.ReadUserClaim("A", "aa")
	require.NoError(t, err)
	require.Equal(t, pk, uc.Subject)
	require.Empty(t, uc.IssuerAccount)
	require.False(t, ts.KeyStore.HasPrivateKey(pk))

	inputs = []interface{}{"bb", false, pk, "0", "0"}
	cmd = CreateAddUserCmd()
	HoistRootFlags(cmd)
	_, err = ExecuteInteractiveCmd(cmd, inputs)
	require.NoError(t, err)

	uc, err = ts.Store.ReadUserClaim("A", "bb")
	require.NoError(t, err)
	require.Equal(t, pk, uc.Subject)
	require.Empty(t, uc.IssuerAccount)
	require.False(t, ts.KeyStore.HasPrivateKey(pk))

	fp := filepath.Join(ts.Dir, "key")
	err = os.WriteFile(fp, sk, 0600)
	require.NoError(t, err)

	inputs = []interface{}{"cc", false, fp, "0", "0"}
	cmd = CreateAddUserCmd()
	HoistRootFlags(cmd)
	_, err = ExecuteInteractiveCmd(cmd, inputs)
	require.NoError(t, err)

	uc, err = ts.Store.ReadUserClaim("A", "cc")
	require.NoError(t, err)
	require.Equal(t, pk, uc.Subject)
	require.Empty(t, uc.IssuerAccount)
	require.False(t, ts.KeyStore.HasPrivateKey(pk))
}

func Test_AddUserWithExistingNkey(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	kp, err := nkeys.CreateUser()
	require.NoError(t, err)
	_, err = ts.KeyStore.Store(kp)
	require.NoError(t, err)
	pk, err := kp.PublicKey()
	require.NoError(t, err)

	_, err = ExecuteCmd(CreateAddUserCmd(), []string{"U", "--public-key", pk}...)
	require.NoError(t, err)
}

func Test_AddUser_BearerToken(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, err := ExecuteCmd(HoistRootFlags(CreateAddUserCmd()), []string{"--name", "UA"}...)
	require.NoError(t, err)

	_, err = ExecuteCmd(HoistRootFlags(CreateAddUserCmd()), []string{"--name", "UB", "--bearer"}...)
	require.NoError(t, err)

	u, err := ts.Store.ReadUserClaim("A", "UA")
	require.NoError(t, err)
	require.False(t, u.BearerToken)

	u, err = ts.Store.ReadUserClaim("A", "UB")
	require.NoError(t, err)
	require.True(t, u.BearerToken)
}

func Test_AddUserWithSigningKeyOnly(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	// create a signing key
	kp, err := nkeys.CreateAccount()
	require.NoError(t, err)
	_, err = ts.KeyStore.Store(kp)
	require.NoError(t, err)
	pk, err := kp.PublicKey()
	require.NoError(t, err)
	require.True(t, ts.KeyStore.HasPrivateKey(pk))

	ts.AddAccount(t, "A")
	_, err = ExecuteCmd(createEditAccount(), []string{"--sk", pk}...)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, ac)
	ts.KeyStore.Remove(ac.Subject)
	require.False(t, ts.KeyStore.HasPrivateKey(ac.Subject))

	_, err = ExecuteCmd(HoistRootFlags(CreateAddUserCmd()), []string{"--name", "AAA"}...)
	require.NoError(t, err)

	claim, err := ts.Store.ReadUserClaim("A", "AAA")
	require.NoError(t, err)
	require.NotEmpty(t, claim.IssuerAccount)
	require.NotEqual(t, claim.Issuer, claim.IssuerAccount)
	require.Equal(t, claim.Issuer, pk)
}

func Test_AddUserWithSigningKeyInteractive(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	// create a signing key
	kp, err := nkeys.CreateAccount()
	require.NoError(t, err)
	_, err = ts.KeyStore.Store(kp)
	require.NoError(t, err)
	pk, err := kp.PublicKey()
	require.NoError(t, err)
	require.True(t, ts.KeyStore.HasPrivateKey(pk))

	ts.AddAccount(t, "A")
	_, err = ExecuteCmd(createEditAccount(), []string{"--sk", pk}...)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, ac)
	require.True(t, ts.KeyStore.HasPrivateKey(ac.Subject))

	inputs := []interface{}{"AAA", true, "0", "0", 1}
	cmd := CreateAddUserCmd()
	HoistRootFlags(cmd)
	_, err = ExecuteInteractiveCmd(cmd, inputs)
	require.NoError(t, err)

	claim, err := ts.Store.ReadUserClaim("A", "AAA")
	require.NoError(t, err)
	require.NotEmpty(t, claim.IssuerAccount)
	require.NotEqual(t, claim.Issuer, claim.IssuerAccount)
	require.Equal(t, claim.Issuer, pk)
}

func Test_AddUser_QueuePermissions(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	_, err := ExecuteCmd(HoistRootFlags(CreateAddUserCmd()), []string{"--name", "UA", "--allow-sub", "foo queue", "--deny-sub", "bar queue"}...)
	require.NoError(t, err)

	u, err := ts.Store.ReadUserClaim("A", "UA")
	require.NoError(t, err)
	require.True(t, u.Sub.Allow.Contains("foo queue"))
	require.True(t, u.Sub.Deny.Contains("bar queue"))
}

func Test_AddUser_SrcPermissions(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	_, err := ExecuteCmd(HoistRootFlags(CreateAddUserCmd()), []string{"--name", "UA", "--source-network", "1.2.1.1/29", "--source-network", "1.2.2.2/29,1.2.0.3/32"}...)
	require.NoError(t, err)

	u, err := ts.Store.ReadUserClaim("A", "UA")
	require.NoError(t, err)
	require.True(t, u.Limits.Src.Contains("1.2.1.1/29"))
	require.True(t, u.Limits.Src.Contains("1.2.2.2/29"))
	require.True(t, u.Limits.Src.Contains("1.2.0.3/32"))
}

func Test_AddUser_Scoped(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	s, pk, kp := CreateAccountKey(t)

	// store seed in temporary file
	f, err := os.CreateTemp("", "")
	defer os.Remove(f.Name())
	require.NoError(t, err)
	f.Write(s)
	f.Sync()

	_, err = ts.KeyStore.Store(kp)
	require.NoError(t, err)

	_, err = ExecuteCmd(createEditAccount(), "--sk", pk)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.SigningKeys, pk)

	_, err = ExecuteCmd(createEditSkopedSkCmd(), []string{"--account", "A", "--sk", pk, "--subs", "5", "--role", "user-role"}...)
	require.NoError(t, err)

	// fail using key outright
	out, err := ExecuteCmd(HoistRootFlags(CreateAddUserCmd()), "--name", "UA", "--tag", "foo", "--bearer", "-K", pk)
	require.Error(t, err)
	require.Contains(t, out.Err, "[ERR ] scoped users require no permissions or limits set")

	// fail using key via role name
	out, err = ExecuteCmd(HoistRootFlags(CreateAddUserCmd()), "--name", "UB", "--tag", "foo", "--bearer", "-K", "user-role")
	require.Error(t, err)
	require.Contains(t, out.Err, "[ERR ] scoped users require no permissions or limits set")

	// pass as no permissions/limits are modified.
	_, err = ExecuteCmd(HoistRootFlags(CreateAddUserCmd()), "--name", "UC", "--tag", "foo", "-K", "user-role")
	require.NoError(t, err)

	// pass as no permissions/limits are modified.
	_, err = ExecuteCmd(HoistRootFlags(CreateAddUserCmd()), "--name", "UD", "--tag", "foo", "-K", pk)
	require.NoError(t, err)

	// pass as no permissions/limits are modified.
	_, err = ExecuteCmd(HoistRootFlags(CreateAddUserCmd()), "--name", "UE", "--tag", "foo", "-K", string(s))
	require.NoError(t, err)

	// pass as no permissions/limits are modified.
	_, err = ExecuteCmd(HoistRootFlags(CreateAddUserCmd()), "--name", "UF", "--tag", "foo", "-K", f.Name())
	require.NoError(t, err)
}

func Test_AddUser_RotateScoped(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	// store seed in temporary file
	newKey := func() string {
		_, pk, kp := CreateAccountKey(t)
		_, err := ts.KeyStore.Store(kp)
		require.NoError(t, err)
		return pk
	}
	pk1 := newKey()
	_, err := ExecuteCmd(createEditAccount(), []string{"--sk", pk1}...)
	require.NoError(t, err)
	_, err = ExecuteCmd(createEditSkopedSkCmd(), []string{"--account", "A", "--sk", pk1, "--subs", "5", "--role", "user-role1"}...)
	require.NoError(t, err)
	// add and edit user
	_, err = ExecuteCmd(HoistRootFlags(CreateAddUserCmd()), []string{"--name", "UA", "--tag", "foo1", "-K", "user-role1"}...)
	require.NoError(t, err)
	_, err = ExecuteCmd(HoistRootFlags(createEditUserCmd()), []string{"--name", "UA", "--tag", "foo2", "-K", "user-role1"}...)
	require.NoError(t, err)
	// create a second key and resign this user with it
	pk2 := newKey()
	_, err = ExecuteCmd(createEditAccount(), []string{"--sk", pk2}...)
	require.NoError(t, err)
	_, err = ExecuteCmd(createEditSkopedSkCmd(), []string{"--account", "A", "--sk", pk2, "--subs", "5", "--role", "user-role2"}...)
	require.NoError(t, err)
	// With the re-signing issue in place, this edit command would fail.
	_, err = ExecuteCmd(HoistRootFlags(createEditUserCmd()), []string{"--name", "UA", "--tag", "foo3", "-K", "user-role2"}...)
	require.NoError(t, err)
}

func Test_AddUsersWithSharedSigningKey(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	// store seed in temporary file
	newKey := func() string {
		_, pk, kp := CreateAccountKey(t)
		_, err := ts.KeyStore.Store(kp)
		require.NoError(t, err)
		return pk
	}

	sk := newKey()

	ts.AddAccount(t, "A")
	_, err := ExecuteCmd(createEditAccount(), []string{"--sk", sk}...)
	require.NoError(t, err)
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	assert.Contains(t, ac.SigningKeys, sk)

	ts.AddAccount(t, "B")
	_, err = ExecuteCmd(createEditAccount(), []string{"B", "--sk", sk}...)
	require.NoError(t, err)
	ac, err = ts.Store.ReadAccountClaim("B")
	require.NoError(t, err)
	assert.Contains(t, ac.SigningKeys, sk)

	_, err = ExecuteCmd(HoistRootFlags(CreateAddUserCmd()), []string{"u", "--account", "A", "-K", sk}...)
	require.NoError(t, err)

	_, err = ExecuteCmd(HoistRootFlags(CreateAddUserCmd()), []string{"u", "--account", "B", "-K", sk}...)
	require.NoError(t, err)
}

func Test_AddUserBadName(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	_, err := ExecuteCmd(CreateAddUserCmd(), []string{"A/B"}...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "name cannot contain '/' or '\\'")
}

func Test_AddUserRequireSk(t *testing.T) {
	ts := NewTestStore(t, "0")
	defer ts.Done(t)

	_, err := ExecuteCmd(createEditOperatorCmd(), []string{"--require-signing-keys", "--sk", "generate"}...)
	require.NoError(t, err)

	ts.AddAccount(t, "A")

	_, err = ExecuteCmd(CreateAddUserCmd(), []string{"U"}...)
	require.Error(t, err)
	require.Equal(t, "unable to issue users when operator requires signing keys and the account has none", err.Error())

	_, err = ExecuteCmd(createEditAccount(), []string{"--sk", "generate"}...)
	require.NoError(t, err)

	_, err = ExecuteCmd(CreateAddUserCmd(), []string{"U"}...)
	require.NoError(t, err)
}
