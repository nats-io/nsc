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
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/nsc/cmd/store"

	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
)

func requireEmptyDir(t *testing.T, dir string) {
	infos, err := ioutil.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, infos, 0)
}

func requireExportedKey(t *testing.T, dir string, pk string) {
	kf := filepath.Join(dir, fmt.Sprintf("%s.nk", pk))
	require.FileExists(t, kf)

	d, err := Read(kf)
	require.NoError(t, err)
	nk, err := nkeys.FromSeed(d)
	require.NoError(t, err)
	vpk, err := nk.PublicKey()
	require.NoError(t, err)
	require.Equal(t, pk, vpk)
}

func requireNotExportedKey(t *testing.T, dir string, pk string) {
	kf := filepath.Join(dir, fmt.Sprintf("%s.nk", pk))
	_, err := os.Stat(kf)
	require.True(t, os.IsNotExist(err))
}

func Test_ExportContext(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	exportDir := filepath.Join(ts.Dir, "export")
	_, _, err := ExecuteCmd(createExportKeysCmd(), "--dir", exportDir)
	require.NoError(t, err)

	opk := ts.GetOperatorPublicKey(t)
	requireExportedKey(t, exportDir, opk)

	apk := ts.GetAccountPublicKey(t, "A")
	requireExportedKey(t, exportDir, apk)

	upk := ts.GetUserPublicKey(t, "A", "U")
	requireExportedKey(t, exportDir, upk)
}

func Test_ExportOnlyContext(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "AA")
	ts.AddUser(t, "AA", "UU")
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	exportDir := filepath.Join(ts.Dir, "export")
	_, _, err := ExecuteCmd(createExportKeysCmd(), "--dir", exportDir)
	require.NoError(t, err)

	opk := ts.GetOperatorPublicKey(t)
	requireExportedKey(t, exportDir, opk)

	apk := ts.GetAccountPublicKey(t, "A")
	requireExportedKey(t, exportDir, apk)

	upk := ts.GetUserPublicKey(t, "A", "U")
	requireExportedKey(t, exportDir, upk)

	aapk := ts.GetAccountPublicKey(t, "AA")
	requireNotExportedKey(t, exportDir, aapk)

	uupk := ts.GetUserPublicKey(t, "AA", "UU")
	requireNotExportedKey(t, exportDir, uupk)
}

func Test_ExportAllContext(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "AA")
	ts.AddUser(t, "AA", "UU")
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	exportDir := filepath.Join(ts.Dir, "export")
	_, _, err := ExecuteCmd(createExportKeysCmd(), "--all", "--dir", exportDir)
	require.NoError(t, err)

	opk := ts.GetOperatorPublicKey(t)
	requireExportedKey(t, exportDir, opk)

	apk := ts.GetAccountPublicKey(t, "A")
	requireExportedKey(t, exportDir, apk)

	upk := ts.GetUserPublicKey(t, "A", "U")
	requireExportedKey(t, exportDir, upk)

	aapk := ts.GetAccountPublicKey(t, "AA")
	requireExportedKey(t, exportDir, aapk)

	uupk := ts.GetUserPublicKey(t, "AA", "UU")
	requireExportedKey(t, exportDir, uupk)
}

func Test_ExportAccount(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "AA")
	ts.AddUser(t, "AA", "UU")
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	exportDir := filepath.Join(ts.Dir, "export")
	_, _, err := ExecuteCmd(createExportKeysCmd(), "--account", "AA", "--dir", exportDir)
	require.NoError(t, err)

	opk := ts.GetOperatorPublicKey(t)
	requireExportedKey(t, exportDir, opk)

	apk := ts.GetAccountPublicKey(t, "A")
	requireNotExportedKey(t, exportDir, apk)

	upk := ts.GetUserPublicKey(t, "A", "U")
	requireNotExportedKey(t, exportDir, upk)

	aapk := ts.GetAccountPublicKey(t, "AA")
	requireExportedKey(t, exportDir, aapk)

	uupk := ts.GetUserPublicKey(t, "AA", "UU")
	requireExportedKey(t, exportDir, uupk)
}

func Test_ExportRemove(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)
	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	opk := ts.GetOperatorPublicKey(t)
	apk := ts.GetAccountPublicKey(t, "A")
	upk := ts.GetUserPublicKey(t, "A", "U")

	exportDir := filepath.Join(ts.Dir, "export")
	_, _, err := ExecuteCmd(createExportKeysCmd(), "--dir", exportDir, "--remove")
	require.NoError(t, err)

	requireExportedKey(t, exportDir, opk)
	requireExportedKey(t, exportDir, apk)
	requireExportedKey(t, exportDir, upk)

	requireEmptyDir(t, filepath.Join(ts.KeysDir, "keys", "O"))
	requireEmptyDir(t, filepath.Join(ts.KeysDir, "keys", "A"))
	requireEmptyDir(t, filepath.Join(ts.KeysDir, "keys", "U"))
}

func Test_ExportNoKeyStore(t *testing.T) {
	ts := NewEmptyStore(t)
	defer ts.Done(t)

	store.KeyStorePath = ts.KeysDir
	_, _, err := ExecuteCmd(createExportKeysCmd(), "--dir", ts.Dir)
	require.Error(t, err)
	require.Equal(t, err.Error(), fmt.Sprintf("keystore `%s` does not exist", ts.KeysDir))
}
