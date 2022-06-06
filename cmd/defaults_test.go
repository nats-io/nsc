/*
 * Copyright 2018-2022 The NATS Authors
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

	ResetForTests()
	tc, err := LoadOrInit(filepath.Join(dir, "config"), dir, "")
	require.NoError(t, err)

	require.Equal(t, dir, tc.StoreRoot)
	require.Equal(t, "", tc.Operator)
	require.Equal(t, "", tc.Account)
}

func TestDefault_LoadNewOnExisting(t *testing.T) {
	ts := NewTestStore(t, "operator")
	ts.AddAccount(t, "A")

	var cc ContextConfig
	cc.StoreRoot = ts.GetStoresRoot()
	fp := filepath.Join(ts.Dir, fmt.Sprintf("%s.json", GetToolName()))
	require.NoError(t, WriteJson(fp, cc))

	ResetForTests()
	tc, err := LoadOrInit(filepath.Join(ts.Dir, "config"), "", "")
	require.NoError(t, err)
	require.NotNil(t, tc)

	require.Equal(t, ts.GetStoresRoot(), tc.StoreRoot)
	require.Equal(t, "operator", tc.Operator)
	require.Equal(t, "A", tc.Account)
}

func TestDefault_LoadNewOnExistingOverride(t *testing.T) {
	ts := NewTestStore(t, "operator")
	ts.AddAccount(t, "A")

	var cc ContextConfig
	cc.StoreRoot = ts.GetStoresRoot()
	fp := filepath.Join(ts.Dir, fmt.Sprintf("%s.json", GetToolName()))
	require.NoError(t, WriteJson(fp, cc))

	ResetForTests()
	dataDir := filepath.Join(ts.Dir, "store")
	tc, err := LoadOrInit(filepath.Join(ts.Dir, "config"), dataDir, "")
	require.NoError(t, err)
	require.NotNil(t, tc)

	require.Equal(t, dataDir, tc.StoreRoot)
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

	info, ok, err := isOperatorDir(x)
	require.NoError(t, err)
	require.False(t, ok)
	require.Empty(t, info)

	odir := filepath.Join(ts.GetStoresRoot(), "O")
	info, ok, err = isOperatorDir(odir)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotEmpty(t, info)
	require.Equal(t, "O", info.Name)

	info, ok, err = isOperatorDir(filepath.Dir(odir))
	require.NoError(t, err)
	require.False(t, ok)
	require.Empty(t, info)
}

func Test_GetCwdStore(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddAccount(t, "B")

	d, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(d)

	// normalize the path representation
	require.NoError(t, os.Chdir(ts.Dir))
	require.Nil(t, GetCwdCtx())

	require.NoError(t, err)
	require.NoError(t, os.Chdir(ts.StoreDir))

	require.NotNil(t, GetCwdCtx())
	EqualPaths(t, ts.StoreDir, GetCwdCtx().StoreRoot)

	odir := filepath.Join(ts.StoreDir, "O")
	require.NoError(t, os.Chdir(odir))

	ctx := GetCwdCtx()
	require.NotNil(t, ctx)
	EqualPaths(t, ts.StoreDir, ctx.StoreRoot)
	require.Equal(t, "O", ctx.Operator)
	require.Equal(t, "", ctx.Account)

	accounts := filepath.Join(odir, "accounts")
	require.NoError(t, os.Chdir(accounts))

	ctx = GetCwdCtx()
	require.NotNil(t, ctx)
	EqualPaths(t, ts.StoreDir, ctx.StoreRoot)
	require.Equal(t, "O", ctx.Operator)
	require.Equal(t, "", ctx.Account)

	actdir := filepath.Join(accounts, "A")
	require.NoError(t, os.Chdir(actdir))

	ctx = GetCwdCtx()
	require.NotNil(t, ctx)
	EqualPaths(t, ts.StoreDir, ctx.StoreRoot)
	require.Equal(t, "O", ctx.Operator)
	require.Equal(t, "A", ctx.Account)

	actdir = filepath.Join(accounts, "B")
	require.NoError(t, os.Chdir(actdir))

	ctx = GetCwdCtx()
	require.NotNil(t, ctx)
	EqualPaths(t, ts.StoreDir, ctx.StoreRoot)
	require.Equal(t, "O", ctx.Operator)
	require.Equal(t, "B", ctx.Account)
}
