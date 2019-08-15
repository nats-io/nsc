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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefault_LoadOrInit(t *testing.T) {
	d := MakeTempDir(t)
	dir := filepath.Join(d, "a")
	require.NoError(t, os.Setenv("TEST_NAME", dir))

	ResetForTests()
	tc, err := LoadOrInit("my/foo", "TEST_NAME")
	require.NoError(t, err)

	require.Equal(t, filepath.Join(dir, "nats"), tc.StoreRoot)
	require.Equal(t, "", tc.Operator)
	require.Equal(t, "", tc.Account)
	require.Equal(t, "my/foo", tc.GithubUpdates)
}

func TestDefault_LoadNewOnExisting(t *testing.T) {
	ts := NewTestStore(t, "operator")
	require.NoError(t, os.Setenv("TEST_NAME", ts.Dir))
	ts.AddAccount(t, "A")

	var cc ContextConfig
	cc.StoreRoot = ts.GetStoresRoot()
	fp := filepath.Join(ts.Dir, fmt.Sprintf("%s.json", GetToolName()))
	require.NoError(t, WriteJson(fp, cc))

	ResetForTests()
	tc, err := LoadOrInit("my/foo", "TEST_NAME")
	require.NoError(t, err)
	require.NotNil(t, tc)

	require.Equal(t, ts.GetStoresRoot(), tc.StoreRoot)
	require.Equal(t, "operator", tc.Operator)
	require.Equal(t, "A", tc.Account)
}

func Test_isOperatorDir(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")

	x := filepath.Join(ts.Dir, "X")
	err := os.Mkdir(x, 0777)
	require.NoError(t, err)

	ok, err := isOperatorDir(x)
	require.NoError(t, err)
	require.False(t, ok)

	odir := filepath.Join(ts.GetStoresRoot(), "O")
	ok, err = isOperatorDir(odir)
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = isOperatorDir(filepath.Dir(odir))
	require.NoError(t, err)
	require.False(t, ok)
}

func Test_GetCwdStore(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")

	d, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(d)

	// normalize the path representation
	require.NoError(t, os.Chdir(ts.Dir))
	testDir, err := os.Getwd()
	require.NoError(t, err)

	require.Equal(t, "", GetCwdStoresRoot())

	storeRoot := filepath.Join(testDir, "store")
	require.NoError(t, err)
	require.NoError(t, os.Chdir(storeRoot))
	require.Equal(t, storeRoot, GetCwdStoresRoot())

	odir := filepath.Join(storeRoot, "O")
	require.NoError(t, os.Chdir(odir))
	require.Equal(t, storeRoot, GetCwdStoresRoot())

	accounts := filepath.Join(odir, "accounts")
	require.NoError(t, os.Chdir(accounts))
	require.Equal(t, storeRoot, GetCwdStoresRoot())

	actdir := filepath.Join(accounts, "A")
	require.NoError(t, os.Chdir(actdir))
	require.Equal(t, storeRoot, GetCwdStoresRoot())
}
