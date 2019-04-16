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
	"strings"
	"testing"

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
		{createEditUserCmd(), []string{"edit", "user", "--tag", "A", "--account", "A"}, nil, []string{"edited user \"a\""}, false},
		{createEditUserCmd(), []string{"edit", "user", "--tag", "B", "--account", "B"}, nil, []string{"user name is required"}, true},
		{createEditUserCmd(), []string{"edit", "user", "--tag", "B", "--account", "B", "--name", "bb"}, nil, []string{"edited user \"bb\""}, false},
	}

	tests.Run(t, "root", "edit")
}

func Test_EditUserAccountRequired(t *testing.T) {
	ts := NewTestStore(t, "edit user")
	defer ts.Done(t)

	ts.AddUser(t, "A", "a")
	ts.AddUser(t, "B", "b")
	GetConfig().SetAccount("")
	_, _, err := ExecuteCmd(createEditUserCmd(), "--tag", "A")
	require.Error(t, err)
	require.Contains(t, err.Error(), "account is required")
}

func Test_EditUser_Tag(t *testing.T) {
	ts := NewTestStore(t, "edit user")
	defer ts.Done(t)

	ts.AddUser(t, "A", "a")
	_, _, err := ExecuteCmd(createEditUserCmd(), "--tag", "A,B,C")
	require.NoError(t, err)

	cc, err := ts.Store.ReadUserClaim("A", "a")
	require.NoError(t, err)
	require.NotNil(t, cc)

	require.Len(t, cc.Tags, 3)
	require.ElementsMatch(t, cc.Tags, []string{"a", "b", "c"})

	_, _, err = ExecuteCmd(createEditUserCmd(), "--rm-tag", "A,B")
	require.NoError(t, err)

	cc, err = ts.Store.ReadUserClaim("A", "a")
	require.NoError(t, err)
	require.NotNil(t, cc)

	require.Len(t, cc.Tags, 1)
	require.ElementsMatch(t, cc.Tags, []string{"c"})

}

func Test_EditUser_Times(t *testing.T) {
	ts := NewTestStore(t, "edit server")
	defer ts.Done(t)

	ts.AddUser(t, "A", "a")

	_, _, err := ExecuteCmd(createEditUserCmd(), "--start", "2018-01-01", "--expiry", "2050-01-01")
	require.NoError(t, err)

	start, err := ParseExpiry("2018-01-01")
	require.NoError(t, err)

	expiry, err := ParseExpiry("2050-01-01")
	require.NoError(t, err)

	cc, err := ts.Store.ReadUserClaim("A", "a")
	require.NoError(t, err)
	require.NotNil(t, cc)
	require.Equal(t, start, cc.NotBefore)
	require.Equal(t, expiry, cc.Expires)
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
	require.ElementsMatch(t, strings.Split(cc.Src, ","), []string{"192.0.2.0/24", "192.0.1.0/8"})

	_, _, err = ExecuteCmd(createEditUserCmd(), "--rm-source-network", "192.0.2.0/24")
	require.NoError(t, err)

	cc, err = ts.Store.ReadUserClaim("A", "a")
	require.NoError(t, err)
	require.NotNil(t, cc)
	require.ElementsMatch(t, strings.Split(cc.Src, ","), []string{"192.0.1.0/8"})
}
