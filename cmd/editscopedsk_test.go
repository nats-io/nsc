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

	ts.AddAccount(t, "A")
	_, pk, _ := CreateAccountKey(t)
	_, pk2, _ := CreateAccountKey(t)

	_, _, err := ExecuteCmd(createEditAccount(), "--sk", pk, "--sk", pk2)
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.SigningKeys, pk)
	require.Contains(t, ac.SigningKeys, pk2)

	_, _, err = ExecuteCmd(createEditSkopedSkCmd(), "--account", "A", "--sk", pk2, "--subs", "5", "--role", "foo",
		"--allow-pub", "foo", "--allow-sub", "foo", "--deny-sub", "bar", "--conn-type", "LEAFNODE", "--data", "5kib", "--bearer")
	require.NoError(t, err)

	ac, err = ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	require.Contains(t, ac.SigningKeys, pk)
	s, ok := ac.SigningKeys.GetScope(pk)
	require.True(t, ok)
	require.Nil(t, s)
	require.Contains(t, ac.SigningKeys, pk2)
	s, ok = ac.SigningKeys.GetScope(pk2)
	require.True(t, ok)
	require.NotNil(t, s)
	us := s.(*jwt.UserScope)
	require.Equal(t, us.Template.Subs, int64(5))
	require.Equal(t, us.Template.Data, int64(5*1024))
	require.True(t, us.Template.AllowedConnectionTypes.Contains("LEAFNODE"))
	require.True(t, us.Template.Sub.Allow.Contains("foo"))
	require.True(t, us.Template.Sub.Deny.Contains("bar"))
	require.True(t, us.Template.Pub.Allow.Contains("foo"))
	require.True(t, us.Template.BearerToken)
	require.Equal(t, us.Role, "foo")
}
