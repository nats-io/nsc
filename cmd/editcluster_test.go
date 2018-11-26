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

func Test_EditCluster(t *testing.T) {
	ts := NewTestStore(t, "edit cluster")
	defer ts.Done(t)

	ts.AddCluster(t, "A")
	ts.AddCluster(t, "B")

	tests := CmdTests{
		{createEditClusterCmd(), []string{"edit", "cluster"}, nil, []string{"specify an edit option"}, true},
		{createEditClusterCmd(), []string{"edit", "cluster", "--tag", "A"}, nil, []string{"a cluster is required"}, true},
		{createEditClusterCmd(), []string{"edit", "cluster", "--tag", "A", "--cluster", "A"}, nil, []string{"edited cluster \"A\""}, false},
	}

	tests.Run(t, "root", "edit")
}

func Test_EditCluster_Tag(t *testing.T) {
	ts := NewTestStore(t, "edit cluster")
	defer ts.Done(t)

	ts.AddCluster(t, "A")
	_, _, err := ExecuteCmd(createEditClusterCmd(), "--tag", "A,B,C")
	require.NoError(t, err)

	cc, err := ts.Store.ReadClusterClaim("A")
	require.NoError(t, err)
	require.NotNil(t, cc)

	require.Len(t, cc.Tags, 3)
	require.ElementsMatch(t, cc.Tags, []string{"a", "b", "c"})
}

func Test_EditCluster_RmTag(t *testing.T) {
	ts := NewTestStore(t, "edit cluster")
	defer ts.Done(t)

	ts.AddCluster(t, "A")
	_, _, err := ExecuteCmd(createEditClusterCmd(), "--tag", "A,B,C")
	require.NoError(t, err)

	_, _, err = ExecuteCmd(createEditClusterCmd(), "--rm-tag", "A,B")
	require.NoError(t, err)

	cc, err := ts.Store.ReadClusterClaim("A")
	require.NoError(t, err)
	require.NotNil(t, cc)

	require.Len(t, cc.Tags, 1)
	require.ElementsMatch(t, cc.Tags, []string{"c"})
}

func Test_EditCluster_Times(t *testing.T) {
	ts := NewTestStore(t, "edit cluster")
	defer ts.Done(t)

	ts.AddCluster(t, "A")

	_, _, err := ExecuteCmd(createEditClusterCmd(), "--start", "2018-01-01", "--expiry", "2050-01-01")
	require.NoError(t, err)

	start, err := ParseExpiry("2018-01-01")
	require.NoError(t, err)

	expiry, err := ParseExpiry("2050-01-01")
	require.NoError(t, err)

	cc, err := ts.Store.ReadClusterClaim("A")
	require.NoError(t, err)
	require.NotNil(t, cc)
	require.Equal(t, start, cc.NotBefore)
	require.Equal(t, expiry, cc.Expires)
}

func Test_EditCluster_Account(t *testing.T) {
	ts := NewTestStore(t, "edit cluster")
	defer ts.Done(t)

	ts.AddCluster(t, "A")

	_, pub, _ := CreateAccountKey(t)

	_, _, err := ExecuteCmd(createEditClusterCmd(), "--trusted-accounts", pub)
	require.NoError(t, err)
	cc, err := ts.Store.ReadClusterClaim("A")
	require.NoError(t, err)
	require.NotNil(t, cc)
	require.Len(t, cc.Accounts, 1)

	_, _, err = ExecuteCmd(createEditClusterCmd(), "--trusted-accounts", "")
	require.NoError(t, err)
	cc, err = ts.Store.ReadClusterClaim("A")
	require.NoError(t, err)
	require.NotNil(t, cc)
	require.Len(t, cc.Accounts, 0)
}

func Test_EditCluster_Trust(t *testing.T) {
	ts := NewTestStore(t, "edit cluster")
	defer ts.Done(t)

	ts.AddCluster(t, "A")

	_, pub, _ := CreateOperatorKey(t)

	_, _, err := ExecuteCmd(createEditClusterCmd(), "--trusted-operators", pub)
	require.NoError(t, err)
	cc, err := ts.Store.ReadClusterClaim("A")
	require.NoError(t, err)
	require.NotNil(t, cc)
	require.Len(t, cc.Trust, 1)

	_, _, err = ExecuteCmd(createEditClusterCmd(), "--trusted-operators", "")
	require.NoError(t, err)
	cc, err = ts.Store.ReadClusterClaim("A")
	require.NoError(t, err)
	require.NotNil(t, cc)
	require.Len(t, cc.Trust, 0)
}

func Test_EditCluster_AccountURL(t *testing.T) {
	ts := NewTestStore(t, "edit cluster")
	defer ts.Done(t)

	ts.AddCluster(t, "A")

	_, _, err := ExecuteCmd(createEditClusterCmd(), "--account-url-template", "test")
	require.NoError(t, err)
	cc, err := ts.Store.ReadClusterClaim("A")
	require.NoError(t, err)
	require.NotNil(t, cc)
	require.Equal(t, "test", cc.AccountURL)

	_, _, err = ExecuteCmd(createEditClusterCmd(), "--account-url-template", "")
	require.NoError(t, err)
	cc, err = ts.Store.ReadClusterClaim("A")
	require.NoError(t, err)
	require.NotNil(t, cc)
	require.Equal(t, "", cc.AccountURL)
}

func Test_EditCluster_OperatorURL(t *testing.T) {
	ts := NewTestStore(t, "edit cluster")
	defer ts.Done(t)

	ts.AddCluster(t, "A")

	_, _, err := ExecuteCmd(createEditClusterCmd(), "--operator-url-template", "test")
	require.NoError(t, err)
	cc, err := ts.Store.ReadClusterClaim("A")
	require.NoError(t, err)
	require.NotNil(t, cc)
	require.Equal(t, "test", cc.OperatorURL)

	_, _, err = ExecuteCmd(createEditClusterCmd(), "--operator-url-template", "")
	require.NoError(t, err)
	cc, err = ts.Store.ReadClusterClaim("A")
	require.NoError(t, err)
	require.NotNil(t, cc)
	require.Equal(t, "", cc.OperatorURL)
}
