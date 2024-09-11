/*
 * Copyright 2018-2021 The NATS Authors
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
	"os"
	"strings"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/stretchr/testify/require"
)

func Test_EditScopedSk_NotFound(t *testing.T) {
	ts := NewTestStore(t, "edit scope")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	_, _, err := ExecuteCmd(createEditSkopedSkCmd(), "--account", "not there")
	require.Error(t, err)

	_, _, err = ExecuteCmd(createEditSkopedSkCmd(), "--account", "A", "--sk", "not there")
	require.Error(t, err)
}

func Test_EditScopedSk_Subs(t *testing.T) {
	ts := NewTestStore(t, "edit scope")
	defer ts.Done(t)

	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)

	ts.AddAccount(t, "A")
	_, pk, _ := CreateAccountKey(t)
	s, pk2, kp := CreateAccountKey(t)

	_, _, err = ExecuteCmd(createEditAccount(), "--sk", pk, "--sk", pk2)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.SigningKeys, pk)
	require.Contains(t, ac.SigningKeys, pk2)
	require.Equal(t, ac.Issuer, oc.Subject)

	checkAcc := func(subs int64) {
		ac, err = ts.Store.ReadAccountClaim("A")
		require.NoError(t, err)
		require.Contains(t, ac.SigningKeys, pk)
		require.Equal(t, ac.Issuer, oc.Subject)
		s, ok := ac.SigningKeys.GetScope(pk)
		require.True(t, ok)
		require.Nil(t, s)
		require.Contains(t, ac.SigningKeys, pk2)
		s, ok = ac.SigningKeys.GetScope(pk2)
		require.True(t, ok)
		require.NotNil(t, s)
		us := s.(*jwt.UserScope)
		require.Equal(t, us.Template.Subs, subs)
		require.Equal(t, us.Template.Data, int64(5*1024))
		require.True(t, us.Template.AllowedConnectionTypes.Contains("LEAFNODE"))
		require.True(t, us.Template.Sub.Allow.Contains("foo"))
		require.True(t, us.Template.Sub.Deny.Contains("bar"))
		require.True(t, us.Template.Pub.Allow.Contains("foo"))
		require.True(t, us.Template.BearerToken)
		require.Equal(t, us.Role, "foo")
	}

	_, _, err = ExecuteCmd(createEditSkopedSkCmd(), "--account", "A", "--sk", pk2, "--subs", "5", "--role", "foo",
		"--allow-pub", "foo", "--allow-sub", "foo", "--deny-sub", "bar", "--conn-type", "LEAFNODE", "--data", "5kib", "--bearer")
	require.NoError(t, err)
	checkAcc(5)
	// update using role name, with key that can't be found
	_, _, err = ExecuteCmd(createEditSkopedSkCmd(), "--account", "A", "--sk", "foo", "--subs", "10")
	require.Error(t, err)

	// store seed in temporary file and keystore so it can be found
	f, err := os.CreateTemp("", "")
	defer os.Remove(f.Name())
	require.NoError(t, err)
	f.Write(s)
	f.Sync()
	_, err = ts.KeyStore.Store(kp)
	require.NoError(t, err)
	// update using role name
	_, _, err = ExecuteCmd(createEditSkopedSkCmd(), "--account", "A", "--sk", "foo", "--subs", "10")
	require.NoError(t, err)

}

func Test_EditScopedSk_ResolveAny(t *testing.T) {
	ts := NewTestStore(t, "edit scope")
	defer ts.Done(t)

	oc, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)

	ts.AddAccount(t, "A")
	s, pk, kp := CreateAccountKey(t)

	fp, err := ts.KeyStore.Store(kp)
	require.NoError(t, err)

	_, _, err = ExecuteCmd(createEditAccount(), "--sk", pk)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.SigningKeys, pk)
	require.Equal(t, ac.Issuer, oc.Subject)

	_, _, err = ExecuteCmd(createEditSkopedSkCmd(), "--account", "A",
		"--sk", string(s), "--subs", "10")
	require.NoError(t, err)

	_, _, err = ExecuteCmd(createEditSkopedSkCmd(), "--account", "A",
		"--sk", pk, "--subs", "10")
	require.NoError(t, err)

	_, _, err = ExecuteCmd(createEditSkopedSkCmd(), "--account", "A",
		"--sk", fp, "--subs", "10")
	require.NoError(t, err)

	_, _, err = ExecuteCmd(createEditSkopedSkCmd(), "--account", "A",
		"--sk", "foo", "--subs", "10")
	require.Error(t, err)
}

func Test_EditScopedSkAddGenerates(t *testing.T) {
	ts := NewTestStore(t, "edit scope")
	defer ts.Done(t)

	_, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)

	ts.AddAccount(t, "A")

	// add the scope with a generate
	_, _, err = ExecuteCmd(createEditSkopedSkCmd(), "--sk", "generate")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.SigningKeys.Keys(), 1)
	pk := ac.SigningKeys.Keys()[0]
	scope, ok := ac.SigningKeys.GetScope(pk)
	require.True(t, ok)
	us, ok := scope.(*jwt.UserScope)
	require.True(t, ok)
	require.NotNil(t, us)

	// get the scope with the key
	_, _, err = ExecuteCmd(createEditSkopedSkCmd(), "--sk", pk, "--role", "foo", "--description", "hello")
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.SigningKeys.Keys(), 1)
	scope, ok = ac.SigningKeys.GetScope(pk)
	require.True(t, ok)
	us, ok = scope.(*jwt.UserScope)
	require.True(t, ok)
	require.NotNil(t, us)
	require.Equal(t, us.Role, "foo")
	require.Equal(t, us.Description, "hello")
}

func Test_EditScopedSkByRole(t *testing.T) {
	ts := NewTestStore(t, "edit scope")
	defer ts.Done(t)

	_, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)

	ts.AddAccount(t, "A")

	// add the scope with a generate
	_, _, err = ExecuteCmd(createEditSkopedSkCmd(), "--sk", "generate", "--role", "foo")
	require.NoError(t, err)

	// get the scope by saying that the key is the role
	_, _, err = ExecuteCmd(createEditSkopedSkCmd(), "--sk", "foo", "--allow-pub", ">")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.SigningKeys.Keys(), 1)
	scope, ok := ac.SigningKeys.GetScope(ac.SigningKeys.Keys()[0])
	require.True(t, ok)
	us, ok := scope.(*jwt.UserScope)
	require.True(t, ok)
	require.NotNil(t, us)
	require.Equal(t, us.Role, "foo")
	require.Len(t, us.Template.Pub.Allow, 1)

	// get the scope by just specifying the role
	_, _, err = ExecuteCmd(createEditSkopedSkCmd(), "--role", "foo", "--allow-sub", ">")
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.SigningKeys.Keys(), 1)
	scope, ok = ac.SigningKeys.GetScope(ac.SigningKeys.Keys()[0])
	require.True(t, ok)
	us, ok = scope.(*jwt.UserScope)
	require.True(t, ok)
	require.NotNil(t, us)
	require.Equal(t, us.Role, "foo")
	require.Len(t, us.Template.Sub.Allow, 1)
}

func Test_EditScopedSkConnType(t *testing.T) {
	ts := NewTestStore(t, "edit scope")
	defer ts.Done(t)

	_, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)

	ts.AddAccount(t, "A")

	// add the scope with a generate
	_, _, err = ExecuteCmd(createEditSkopedSkCmd(), "--sk", "generate", "--role", "foo")
	require.NoError(t, err)

	// try to add invalid conn type
	_, _, err = ExecuteCmd(createEditSkopedSkCmd(), "--sk", "foo", "--conn-type", "bar")
	require.Error(t, err)

	// add lower case conn type - this is prevented now, but worked in the past
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	scope, ok := ac.SigningKeys.GetScope(ac.SigningKeys.Keys()[0])
	require.True(t, ok)
	scope.(*jwt.UserScope).Template.AllowedConnectionTypes.Add(strings.ToLower(jwt.ConnectionTypeStandard))
	ac.SigningKeys.AddScopedSigner(scope)
	token, err := ac.Encode(ts.OperatorKey)
	require.NoError(t, err)
	ts.Store.StoreClaim([]byte(token))
	// test if lower case conn type was added correctly to the sk
	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.SigningKeys.Keys(), 1)
	scope, ok = ac.SigningKeys.GetScope(ac.SigningKeys.Keys()[0])
	require.True(t, ok)
	us, ok := scope.(*jwt.UserScope)
	require.True(t, ok)
	require.NotNil(t, us)
	require.Len(t, us.Template.AllowedConnectionTypes, 1)
	require.Equal(t, strings.ToLower(jwt.ConnectionTypeStandard), us.Template.AllowedConnectionTypes[0])

	// add lower case conn type - should be transformed upper case
	_, _, err = ExecuteCmd(createEditSkopedSkCmd(), "--sk", "foo", "--conn-type", strings.ToLower(jwt.ConnectionTypeMqtt))
	require.NoError(t, err)
	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.SigningKeys.Keys(), 1)
	scope, ok = ac.SigningKeys.GetScope(ac.SigningKeys.Keys()[0])
	require.True(t, ok)
	us, ok = scope.(*jwt.UserScope)
	require.True(t, ok)
	require.NotNil(t, us)
	require.Len(t, us.Template.AllowedConnectionTypes, 2)
	require.Equal(t, jwt.ConnectionTypeMqtt, us.Template.AllowedConnectionTypes[1])

	// test if the set above fixed the lower case conn type added before
	require.Equal(t, jwt.ConnectionTypeStandard, us.Template.AllowedConnectionTypes[0])
}

func Test_EditScopedSkRmConnType(t *testing.T) {
	ts := NewTestStore(t, "edit scope")
	defer ts.Done(t)

	_, err := ts.Store.ReadOperatorClaim()
	require.NoError(t, err)

	ts.AddAccount(t, "A")

	// add the scope with a generate
	_, _, err = ExecuteCmd(createEditSkopedSkCmd(), "--sk", "generate", "--role", "foo")
	require.NoError(t, err)

	// add lower case conn types - this is prevented now, but worked in the past
	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	scope, ok := ac.SigningKeys.GetScope(ac.SigningKeys.Keys()[0])
	require.True(t, ok)
	scope.(*jwt.UserScope).Template.AllowedConnectionTypes.Add(strings.ToLower(jwt.ConnectionTypeStandard))
	scope.(*jwt.UserScope).Template.AllowedConnectionTypes.Add(strings.ToLower(jwt.ConnectionTypeWebsocket))
	ac.SigningKeys.AddScopedSigner(scope)
	token, err := ac.Encode(ts.OperatorKey)
	require.NoError(t, err)
	ts.Store.StoreClaim([]byte(token))
	// test if lower case conn type was added correctly to the sk
	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.SigningKeys.Keys(), 1)
	scope, ok = ac.SigningKeys.GetScope(ac.SigningKeys.Keys()[0])
	require.True(t, ok)
	us, ok := scope.(*jwt.UserScope)
	require.True(t, ok)
	require.NotNil(t, us)
	require.Len(t, us.Template.AllowedConnectionTypes, 2)
	require.Equal(t, strings.ToLower(jwt.ConnectionTypeStandard), us.Template.AllowedConnectionTypes[0])
	require.Equal(t, strings.ToLower(jwt.ConnectionTypeWebsocket), us.Template.AllowedConnectionTypes[1])

	// remove first conn type via lower cased input
	_, _, err = ExecuteCmd(createEditSkopedSkCmd(), "--sk", "foo", "--rm-conn-type", strings.ToLower(jwt.ConnectionTypeStandard))
	require.NoError(t, err)
	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.SigningKeys.Keys(), 1)
	scope, ok = ac.SigningKeys.GetScope(ac.SigningKeys.Keys()[0])
	require.True(t, ok)
	us, ok = scope.(*jwt.UserScope)
	require.True(t, ok)
	require.NotNil(t, us)
	require.Len(t, us.Template.AllowedConnectionTypes, 1)
	// remove second conn type via upper cased input
	_, _, err = ExecuteCmd(createEditSkopedSkCmd(), "--sk", "foo", "--rm-conn-type", jwt.ConnectionTypeWebsocket)
	require.NoError(t, err)
	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Len(t, ac.SigningKeys.Keys(), 1)
	scope, ok = ac.SigningKeys.GetScope(ac.SigningKeys.Keys()[0])
	require.True(t, ok)
	us, ok = scope.(*jwt.UserScope)
	require.True(t, ok)
	require.NotNil(t, us)
	require.Len(t, us.Template.AllowedConnectionTypes, 0)
}
