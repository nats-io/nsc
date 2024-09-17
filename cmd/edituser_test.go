/*
 * Copyright 2018-2024 The NATS Authors
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
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nsc/v2/cmd/store"

	"github.com/nats-io/nkeys"

	cli "github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/require"
)

func Test_EditUser(t *testing.T) {
	ts := NewTestStore(t, "edit user")
	defer ts.Done(t)

	ts.AddUser(t, "A", "a")
	ts.AddUser(t, "B", "b")
	ts.AddUser(t, "B", "bb")

	tests := CmdTests{
		{createEditUserCmd(), []string{"edit", "user"}, nil, []string{"specify an edit option"}, true},
		{createEditUserCmd(), []string{"edit", "user", "--tag", "A", "--account", "A"}, nil, []string{"--tag \"A\" is not lowercased"}, true},
		{createEditUserCmd(), []string{"edit", "user", "--tag", "a", "--account", "A"}, nil, []string{"edited user \"a\""}, false},
		{createEditUserCmd(), []string{"edit", "user", "--conn-type", "MQTT", "--rm-conn-type", "LEAFNODE", "--account", "A"}, nil, []string{"added connection type MQTT", "added connection type MQTT"}, false},
		{createEditUserCmd(), []string{"edit", "user", "--conn-type", "LEAFNODE_WS", "--account", "A"}, nil, []string{"added connection type LEAFNODE_WS"}, false},
		{createEditUserCmd(), []string{"edit", "user", "--conn-type", "MQTT_WS", "--account", "A"}, nil, []string{"added connection type MQTT_WS"}, false},
		{createEditUserCmd(), []string{"edit", "user", "--tag", "b", "--account", "B"}, nil, []string{"user name is required"}, true},
		{createEditUserCmd(), []string{"edit", "user", "--tag", "b", "--account", "B", "--name", "bb"}, nil, []string{"edited user \"bb\""}, false},
	}

	tests.Run(t, "root", "edit")
}

func Test_EditUserInteractive(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddUser(t, "A", "U")

	inputs := []interface{}{"-1", "2018-01-01", "2050-01-01", false}
	cli.LogFn = t.Log
	_, _, err := ExecuteInteractiveCmd(createEditUserCmd(), inputs)
	require.NoError(t, err)

	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)

	start, err := ParseExpiry("2018-01-01")
	require.NoError(t, err)
	require.Equal(t, start, uc.NotBefore)

	expire, err := ParseExpiry("2050-01-01")
	require.NoError(t, err)
	require.Equal(t, expire, uc.Expires)
	require.Nil(t, uc.Resp)
}

func Test_EditUserEditResponsePermissions(t *testing.T) {
	t.Skip("response permissions not interactive")
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddUser(t, "A", "U")

	inputs := []interface{}{true, 100, "1000ms", -1, 0, 0, false}
	_, _, err := ExecuteInteractiveCmd(createEditUserCmd(), inputs)
	require.NoError(t, err)

	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)

	require.NotNil(t, uc.Resp)
	require.Equal(t, 100, uc.Resp.MaxMsgs)
	require.Equal(t, time.Millisecond*1000, uc.Resp.Expires)
}

func Test_EditUserAccountRequired(t *testing.T) {
	ts := NewTestStore(t, "edit user")
	defer ts.Done(t)

	ts.AddUser(t, "A", "a")
	ts.AddUser(t, "B", "b")
	require.NoError(t, GetConfig().SetAccount(""))
	_, _, err := ExecuteCmd(createEditUserCmd(), "--tag", "A")
	require.Error(t, err)
	require.Contains(t, err.Error(), "account is required")
}

func Test_EditUser_Tag(t *testing.T) {
	ts := NewTestStore(t, "edit user")
	defer ts.Done(t)

	ts.AddUser(t, "A", "a")
	_, _, err := ExecuteCmd(createEditUserCmd(), "--tag", "A,B,C", "--strict-tags")
	require.NoError(t, err)

	cc, err := ts.Store.ReadUserClaim("A", "a")
	require.NoError(t, err)
	require.NotNil(t, cc)

	require.Len(t, cc.Tags, 3)
	require.ElementsMatch(t, cc.Tags, []string{"A", "B", "C"})

	_, _, err = ExecuteCmd(createEditUserCmd(), "--rm-tag", "A,B", "--strict-tags")
	require.NoError(t, err)

	cc, err = ts.Store.ReadUserClaim("A", "a")
	require.NoError(t, err)
	require.NotNil(t, cc)

	require.Len(t, cc.Tags, 1)
	require.ElementsMatch(t, cc.Tags, []string{"C"})

}

func Test_EditUser_Pubs(t *testing.T) {
	ts := NewTestStore(t, "edit user")
	defer ts.Done(t)

	ts.AddUser(t, "A", "a")

	_, _, err := ExecuteCmd(createEditUserCmd(), "--allow-pub", "a,b", "--allow-pubsub", "c", "--deny-pub", "foo", "--deny-pubsub", "bar")
	require.NoError(t, err)

	cc, err := ts.Store.ReadUserClaim("A", "a")
	require.NoError(t, err)
	require.NotNil(t, cc)
	require.ElementsMatch(t, cc.Pub.Allow, []string{"a", "b", "c"})
	require.ElementsMatch(t, cc.Sub.Allow, []string{"c"})
	require.ElementsMatch(t, cc.Pub.Deny, []string{"foo", "bar"})
	require.ElementsMatch(t, cc.Sub.Deny, []string{"bar"})

	_, _, err = ExecuteCmd(createEditUserCmd(), "--rm", "c,bar")
	require.NoError(t, err)
	cc, err = ts.Store.ReadUserClaim("A", "a")
	require.NoError(t, err)
	require.NotNil(t, cc)

	require.ElementsMatch(t, cc.Pub.Allow, []string{"a", "b"})
	require.Len(t, cc.Sub.Allow, 0)
	require.ElementsMatch(t, cc.Pub.Deny, []string{"foo"})
	require.Len(t, cc.Sub.Deny, 0)
}

func Test_EditUser_Src(t *testing.T) {
	ts := NewTestStore(t, "edit user")
	defer ts.Done(t)

	ts.AddUser(t, "A", "a")

	_, _, err := ExecuteCmd(createEditUserCmd(), "--source-network", "192.0.2.0/24,192.0.1.0/8")
	require.NoError(t, err)

	cc, err := ts.Store.ReadUserClaim("A", "a")
	require.NoError(t, err)
	require.NotNil(t, cc)
	require.ElementsMatch(t, cc.Src, []string{"192.0.2.0/24", "192.0.1.0/8"})

	_, _, err = ExecuteCmd(createEditUserCmd(), "--rm-source-network", "192.0.2.0/24")
	require.NoError(t, err)

	cc, err = ts.Store.ReadUserClaim("A", "a")
	require.NoError(t, err)
	require.NotNil(t, cc)
	require.ElementsMatch(t, cc.Src, []string{"192.0.1.0/8"})
}

func Test_EditUser_Times(t *testing.T) {
	ts := NewTestStore(t, "edit user")
	defer ts.Done(t)

	ts.AddUser(t, "A", "a")

	_, _, err := ExecuteCmd(createEditUserCmd(), "--time", "16:04:05-17:04:09", "--time", "18:04:05-19:04:09", "--locale", "America/New_York")
	require.NoError(t, err)

	cc, err := ts.Store.ReadUserClaim("A", "a")
	require.NoError(t, err)
	require.NotNil(t, cc)

	require.ElementsMatch(t, cc.Times, []jwt.TimeRange{
		{Start: "16:04:05", End: "17:04:09"},
		{Start: "18:04:05", End: "19:04:09"}})
	require.Equal(t, "America/New_York", cc.Locale)

	_, _, err = ExecuteCmd(createEditUserCmd(), "--rm-time", "16:04:05", "--locale", "")
	require.NoError(t, err)

	cc, err = ts.Store.ReadUserClaim("A", "a")
	require.NoError(t, err)
	require.NotNil(t, cc)
	require.ElementsMatch(t, cc.Times, []jwt.TimeRange{
		{Start: "18:04:05", End: "19:04:09"}})
	require.Equal(t, "UTC", cc.Locale)
}

func Test_EditUserSK(t *testing.T) {
	ts := NewTestStore(t, "O")
	t.Log(ts.Dir)

	s, p, _ := CreateAccountKey(t)
	ts.AddAccount(t, "A")
	_, _, err := ExecuteCmd(HoistRootFlags(createEditAccount()), "--name", "A", "--sk", p)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.SigningKeys, p)

	ts.AddUser(t, "A", "U")
	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Equal(t, uc.Issuer, ac.Subject)
	require.Empty(t, uc.IssuerAccount)

	_, _, err = ExecuteCmd(HoistRootFlags(createEditUserCmd()), "-n", "U", "--allow-pub", "foo", "-K", string(s))
	require.NoError(t, err)
	uc, err = ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Equal(t, uc.Issuer, p)
	require.Equal(t, uc.IssuerAccount, ac.Subject)
}

func Test_EditUserAddedWithSK(t *testing.T) {
	ts := NewTestStore(t, "O")
	t.Log(ts.Dir)

	s, p, sk := CreateAccountKey(t)
	ts.AddAccount(t, "A")
	_, _, err := ExecuteCmd(HoistRootFlags(createEditAccount()), "--name", "A", "--sk", p)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.SigningKeys, p)

	ts.AddUserWithSigner(t, "A", "U", sk)
	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Equal(t, uc.Issuer, p)
	require.Equal(t, uc.IssuerAccount, ac.Subject)

	_, _, err = ExecuteCmd(HoistRootFlags(createEditUserCmd()), "-n", "U", "--allow-pub", "foo", "-K", string(s))
	require.NoError(t, err)
	uc, err = ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Equal(t, uc.Issuer, p)
	require.Equal(t, uc.IssuerAccount, ac.Subject)
}

func Test_EditUser_Payload(t *testing.T) {
	ts := NewTestStore(t, "edit user")
	defer ts.Done(t)

	ts.AddUser(t, "A", "U")

	_, _, err := ExecuteCmd(createEditUserCmd(), "--payload", "1000")
	require.NoError(t, err)

	cc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.NotNil(t, cc)
	require.Equal(t, int64(1000), cc.Limits.Payload)

	_, _, err = ExecuteCmd(createEditUserCmd(), "--payload", "-1")
	require.NoError(t, err)

	cc, err = ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.NotNil(t, cc)
	require.Equal(t, int64(jwt.NoLimit), cc.Limits.Payload)
}

func Test_EditUserResponsePermissions(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	_, _, err := ExecuteCmd(CreateAddUserCmd(), "U", "--max-responses", "100", "--response-ttl", "2ms")
	require.NoError(t, err)

	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.NotNil(t, uc.Resp)

	_, _, err = ExecuteCmd(createEditUserCmd(), "--max-responses", "1000", "--response-ttl", "4ms")
	require.NoError(t, err)

	uc, err = ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.NotNil(t, uc.Resp)
	require.Equal(t, 1000, uc.Resp.MaxMsgs)
	d, _ := time.ParseDuration("4ms")
	require.Equal(t, d, uc.Resp.Expires)

	_, _, err = ExecuteCmd(createEditUserCmd(), "--rm-response-perms")
	require.NoError(t, err)

	uc, err = ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Nil(t, uc.Resp)
}

func Test_EditUserResponsePermissions2(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	_, _, err := ExecuteCmd(CreateAddUserCmd(), "U", "--allow-pub-response", "--response-ttl", "2ms")
	require.NoError(t, err)
	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.NotNil(t, uc.Resp)
	require.Equal(t, 1, uc.Resp.MaxMsgs)

	_, _, err = ExecuteCmd(createEditUserCmd(), "U", "--allow-pub-response=100", "--response-ttl", "2ms")
	require.NoError(t, err)

	uc, err = ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.NotNil(t, uc.Resp)
	require.Equal(t, 100, uc.Resp.MaxMsgs)

	_, _, err = ExecuteCmd(createEditUserCmd(), "--rm-response-perms")
	require.NoError(t, err)

	uc, err = ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Nil(t, uc.Resp)
}

func Test_EditUserBearerToken(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	_, _, err := ExecuteCmd(CreateAddUserCmd(), "U")
	require.NoError(t, err)

	u, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.False(t, u.BearerToken)

	_, stderr, err := ExecuteCmd(createEditUserCmd(), "--name", "U", "--bearer")
	require.NoError(t, err)
	require.Contains(t, stderr, "changed bearer to true")

	u, err = ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.True(t, u.BearerToken)

	_, stderr, err = ExecuteCmd(createEditUserCmd(), "--name", "U", "--bearer=false")
	require.NoError(t, err)
	require.Contains(t, stderr, "ignoring change to bearer - value is already false")

	u, err = ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.False(t, u.BearerToken)
}

func Test_EditUserWithSigningKeyOnly(t *testing.T) {
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
	_, _, err = ExecuteCmd(createEditAccount(), "--sk", pk)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, ac)
	require.NoError(t, ts.KeyStore.Remove(ac.Subject))
	require.False(t, ts.KeyStore.HasPrivateKey(ac.Subject))

	_, _, err = ExecuteCmd(HoistRootFlags(CreateAddUserCmd()), "--name", "AAA")
	require.NoError(t, err)
	_, _, err = ExecuteCmd(HoistRootFlags(createEditUserCmd()), "--name", "AAA", "--payload", "5")
	require.NoError(t, err)

	claim, err := ts.Store.ReadUserClaim("A", "AAA")
	require.NoError(t, err)
	require.Equal(t, claim.Limits.Payload, int64(5))
	require.NotEmpty(t, claim.IssuerAccount)
	require.NotEqual(t, claim.Issuer, claim.IssuerAccount)
	require.Equal(t, claim.Issuer, pk)
}

func Test_EditUserWithSigningKeyInteractive(t *testing.T) {
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
	_, _, err = ExecuteCmd(createEditAccount(), "--sk", pk)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.NotNil(t, ac)
	require.True(t, ts.KeyStore.HasPrivateKey(ac.Subject))

	_, _, err = ExecuteCmd(HoistRootFlags(CreateAddUserCmd()), "--name", "AAA")
	require.NoError(t, err)

	inputs := []interface{}{1, "5", "0", "0", false}
	cmd := createEditUserCmd()
	HoistRootFlags(cmd)
	_, _, err = ExecuteInteractiveCmd(cmd, inputs, "--name", "AAA")
	require.NoError(t, err)

	claim, err := ts.Store.ReadUserClaim("A", "AAA")
	require.NoError(t, err)
	require.Equal(t, claim.Limits.Payload, int64(5))
	require.NotEmpty(t, claim.IssuerAccount)
	require.NotEqual(t, claim.Issuer, claim.IssuerAccount)
	require.Equal(t, claim.Issuer, pk)
}

func Test_EditUserSk(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	sk, err := nkeys.CreateAccount()
	require.NoError(t, err)
	_, err = ts.KeyStore.Store(sk)
	require.NoError(t, err)
	pSk, err := sk.PublicKey()
	require.NoError(t, err)

	_, _, err = ExecuteCmd(createEditAccount(), "--sk", pSk)
	require.NoError(t, err)

	ts.AddUserWithSigner(t, "A", "u", sk)
	uc, err := ts.Store.ReadUserClaim("A", "u")
	require.NoError(t, err)
	require.Equal(t, uc.Issuer, pSk)

	_, _, err = ExecuteCmd(createEditUserCmd(), "--tag", "foo")
	require.NoError(t, err)
	uc, err = ts.Store.ReadUserClaim("A", "u")
	require.NoError(t, err)
	require.Equal(t, uc.Issuer, pSk)
}

func Test_EditUserSubs(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")
	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Equal(t, int64(-1), uc.Subs)

	_, _, err = ExecuteCmd(createEditUserCmd(), "--subs", "100")
	require.NoError(t, err)
	uc, err = ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Equal(t, int64(100), uc.Subs)
	require.NoError(t, err)
}

func Test_EditUserData(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")
	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Equal(t, int64(-1), uc.Limits.Data)

	_, _, err = ExecuteCmd(HoistRootFlags(createEditUserCmd()), "--data", "1Kib")
	require.NoError(t, err)
	uc, err = ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Equal(t, int64(1024), uc.Limits.Data)
	require.NoError(t, err)
}

func Test_EditUserConnection(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	_, _, err := ExecuteCmd(createEditUserCmd(), "--conn-type", "hello")
	require.Error(t, err)

	_, _, err = ExecuteCmd(createEditUserCmd(), "--conn-type", jwt.ConnectionTypeInProcess)
	require.NoError(t, err)
}

func Test_EditUserConnectionCase(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	akp, err := ts.KeyStore.GetKeyPair(ac.Subject)
	require.NoError(t, err)

	claim, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)

	// add lower case conn type - this is prevented now, but worked in the past
	claim.AllowedConnectionTypes.Add(strings.ToLower(jwt.ConnectionTypeStandard))
	token, err := claim.Encode(akp)
	require.NoError(t, err)

	err = ts.Store.Write([]byte(token), store.Accounts, "A", store.Users, store.JwtName("U"))
	require.NoError(t, err)

	claim, err = ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Len(t, claim.AllowedConnectionTypes, 1)
	require.Contains(t, claim.AllowedConnectionTypes, strings.ToLower(jwt.ConnectionTypeStandard))

	_, _, err = ExecuteCmd(createEditUserCmd(), "--conn-type", strings.ToLower(jwt.ConnectionTypeMqtt))
	require.NoError(t, err)

	claim, err = ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Len(t, claim.AllowedConnectionTypes, 2)
	require.Contains(t, claim.AllowedConnectionTypes, jwt.ConnectionTypeMqtt)
	// we expect the set fixed it
	require.Contains(t, claim.AllowedConnectionTypes, jwt.ConnectionTypeStandard)
}

func Test_EditUserConnectionDeleteCase(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	akp, err := ts.KeyStore.GetKeyPair(ac.Subject)
	require.NoError(t, err)

	claim, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)

	// add lower case conn type - this is prevented now, but worked in the past
	claim.AllowedConnectionTypes.Add(strings.ToLower(jwt.ConnectionTypeStandard))
	token, err := claim.Encode(akp)
	require.NoError(t, err)

	err = ts.Store.Write([]byte(token), store.Accounts, "A", store.Users, store.JwtName("U"))
	require.NoError(t, err)

	claim, err = ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Len(t, claim.AllowedConnectionTypes, 1)
	require.Contains(t, claim.AllowedConnectionTypes, strings.ToLower(jwt.ConnectionTypeStandard))

	_, _, err = ExecuteCmd(createEditUserCmd(), "--rm-conn-type", jwt.ConnectionTypeStandard)
	require.NoError(t, err)

	claim, err = ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.Len(t, claim.AllowedConnectionTypes, 0)
}

func TestEditUserStrictTags(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	_, _, err := ExecuteCmd(createEditUserCmd(), "--tag", "a")
	require.NoError(t, err)

	_, _, err = ExecuteCmd(createEditUserCmd(), "--rm-tag", "A")
	require.Error(t, err)
	require.Contains(t, err.Error(), "--rm-tag \"A\" is not lowercased")

	_, _, err = ExecuteCmd(createEditUserCmd(), "--rm-tag", "A", "--strict-tags")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to remove tag: \"A\" - not found")

	_, _, err = ExecuteCmd(createEditUserCmd(), "--tag", "A", "--strict-tags")
	require.NoError(t, err)

	uc, err := ts.Store.ReadUserClaim("A", "U")
	require.NoError(t, err)
	require.True(t, uc.Tags.Equals(&jwt.TagList{"A", "a"}))
}
