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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefault_LoadOrInit(t *testing.T) {
	d := MakeTempDir(t)
	dir := filepath.Join(d, "a")
	require.NoError(t, os.Setenv("TEST_NAME", dir))

	ResetConfigForTests()
	err := LoadOrInit("my/foo", "TEST_NAME")
	require.NoError(t, err)

	tc := GetConfig()
	require.Equal(t, filepath.Join(dir, "nats"), tc.StoreRoot) // store root is the nats folder under the dir
	require.Equal(t, "", tc.Operator)
	require.Equal(t, "", tc.Account)
	require.Equal(t, "", tc.Cluster)
	require.Equal(t, "my/foo", tc.GithubUpdates)
}

func TestDefault_LoadNewOnExisting(t *testing.T) {
	ts := NewTestStore(t, "operator")
	require.NoError(t, os.Setenv("TEST_NAME", ts.Dir))
	ts.AddAccount(t, "A")
	ts.AddCluster(t, "C")

	// This overwrites the config
	/*
		var cc ContextConfig
		cc.StoreRoot = ts.GetStoresRoot()
		fp := filepath.Join(ts.Dir, fmt.Sprintf("%s.json", filepath.Base(os.Args[0])))
		require.NoError(t, WriteJson(fp, cc))
	*/

	ResetConfigForTests()
	err := LoadOrInit("my/foo", "TEST_NAME")
	require.NoError(t, err)

	tc := GetConfig()
	require.Equal(t, ts.GetStoresRoot(), tc.StoreRoot)
	require.Equal(t, "operator", tc.Operator)
	require.Equal(t, "A", tc.Account)
	require.Equal(t, "C", tc.Cluster)
}
