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

func Test_EditServer(t *testing.T) {
	ts := NewTestStore(t, "edit server")
	defer ts.Done(t)

	ts.AddServer(t, "A", "a")
	ts.AddServer(t, "B", "b")
	ts.AddServer(t, "B", "bb")

	tests := CmdTests{
		{createEditServerCmd(), []string{"edit", "server"}, nil, []string{"specify an edit option"}, true},
		{createEditServerCmd(), []string{"edit", "server", "--tag", "A"}, nil, []string{"a cluster is required"}, true},
		{createEditServerCmd(), []string{"edit", "server", "--tag", "A", "--cluster", "A"}, nil, []string{"edited server \"a\""}, false},
		{createEditServerCmd(), []string{"edit", "server", "--tag", "B", "--cluster", "B"}, nil, []string{"server name is required"}, true},
		{createEditServerCmd(), []string{"edit", "server", "--tag", "B", "--cluster", "B", "--name", "bb"}, nil, []string{"edited server \"bb\""}, false},
	}

	tests.Run(t, "root", "edit")
}

func Test_EditServer_Tag(t *testing.T) {
	ts := NewTestStore(t, "edit server")
	defer ts.Done(t)

	ts.AddServer(t, "A", "a")
	_, _, err := ExecuteCmd(createEditServerCmd(), "--tag", "A,B,C")
	require.NoError(t, err)

	cc, err := ts.Store.ReadServerClaim("A", "a")
	require.NoError(t, err)
	require.NotNil(t, cc)

	require.Len(t, cc.Tags, 3)
	require.ElementsMatch(t, cc.Tags, []string{"a", "b", "c"})

	_, _, err = ExecuteCmd(createEditServerCmd(), "--rm-tag", "A,B")
	require.NoError(t, err)

	cc, err = ts.Store.ReadServerClaim("A", "a")
	require.NoError(t, err)
	require.NotNil(t, cc)

	require.Len(t, cc.Tags, 1)
	require.ElementsMatch(t, cc.Tags, []string{"c"})

}

func Test_EditServer_Times(t *testing.T) {
	ts := NewTestStore(t, "edit server")
	defer ts.Done(t)

	ts.AddServer(t, "A", "a")

	_, _, err := ExecuteCmd(createEditServerCmd(), "--start", "2018-01-01", "--expiry", "2050-01-01")
	require.NoError(t, err)

	start, err := ParseExpiry("2018-01-01")
	require.NoError(t, err)

	expiry, err := ParseExpiry("2050-01-01")
	require.NoError(t, err)

	cc, err := ts.Store.ReadServerClaim("A", "a")
	require.NoError(t, err)
	require.NotNil(t, cc)
	require.Equal(t, start, cc.NotBefore)
	require.Equal(t, expiry, cc.Expires)
}
