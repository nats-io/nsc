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
	"fmt"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
)

func storeKeys(t *testing.T, dir string) []nkeys.KeyPair {
	require.NoError(t, MaybeMakeDir(dir))
	os, opk, okp := CreateOperatorKey(t)
	err := WriteFile(filepath.Join(dir, fmt.Sprintf("%s.nk", opk)), os)
	require.NoError(t, err)
	as, apk, akp := CreateAccountKey(t)
	err = WriteFile(filepath.Join(dir, fmt.Sprintf("%s.nk", apk)), as)
	require.NoError(t, err)
	us, upk, ukp := CreateUserKey(t)
	err = WriteFile(filepath.Join(dir, fmt.Sprintf("%s.nk", upk)), us)
	require.NoError(t, err)

	return []nkeys.KeyPair{okp, akp, ukp}
}

func Test_ImportKeys(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	dir := filepath.Join(ts.Dir, "external")
	keys := storeKeys(t, dir)
	require.True(t, len(keys) > 0)

	_, err := ExecuteCmd(createImportKeysCmd(), []string{"--dir", dir}...)
	require.NoError(t, err)
	for _, kp := range keys {
		pk, err := kp.PublicKey()
		require.NoError(t, err)
		nk, err := ts.KeyStore.GetKeyPair(pk)
		require.NoError(t, err)
		require.NotNil(t, nk)
	}
}

func Test_ImportKeysNotRecursive(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	dir := filepath.Join(ts.Dir, "external")
	keys := storeKeys(t, dir)
	require.True(t, len(keys) > 0)
	dir2 := filepath.Join(dir, "more")
	keys2 := storeKeys(t, dir2)
	require.True(t, len(keys2) > 0)

	_, err := ExecuteCmd(createImportKeysCmd(), []string{"--dir", dir}...)
	require.NoError(t, err)
	for _, kp := range keys {
		pk, err := kp.PublicKey()
		require.NoError(t, err)
		nk, err := ts.KeyStore.GetKeyPair(pk)
		require.NoError(t, err)
		require.NotNil(t, nk)
	}
	for _, kp := range keys2 {
		pk, err := kp.PublicKey()
		require.NoError(t, err)
		nk, err := ts.KeyStore.GetKeyPair(pk)
		require.NoError(t, err)
		require.Nil(t, nk)
	}
}

func Test_ImportKeyRecursive(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	dir := filepath.Join(ts.Dir, "external")
	keys := storeKeys(t, dir)
	require.True(t, len(keys) > 0)
	dir2 := filepath.Join(dir, "more")
	keys2 := storeKeys(t, dir2)
	require.True(t, len(keys2) > 0)

	_, err := ExecuteCmd(createImportKeysCmd(), []string{"--dir", dir, "--recurse"}...)
	require.NoError(t, err)
	keys = append(keys, keys2...)
	for _, kp := range keys {
		pk, err := kp.PublicKey()
		require.NoError(t, err)
		nk, err := ts.KeyStore.GetKeyPair(pk)
		require.NoError(t, err)
		require.NotNil(t, nk)
	}
}
