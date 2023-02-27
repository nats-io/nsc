/*
 * Copyright 2018-2023 The NATS Authors
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

	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/stretchr/testify/require"
)

func requireEmptyDir(t *testing.T, dir string) {
	dirEntries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, dirEntries, 0)
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

	upk := ts.GetUserPublicKey(t, "AA", "UU")
	_, _, err := ExecuteCmd(createEditAuthorizationCallout(), "--account", "AA", "--auth-user", upk, "--curve", "generate")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("AA")
	require.NoError(t, err)
	xpk := ac.Authorization.XKey

	exportDir := filepath.Join(ts.Dir, "export")

	_, _, err = ExecuteCmd(createExportKeysCmd(), "--all", "--dir", exportDir)
	require.NoError(t, err)

	opk := ts.GetOperatorPublicKey(t)
	requireExportedKey(t, exportDir, opk)

	apk := ts.GetAccountPublicKey(t, "A")
	requireExportedKey(t, exportDir, apk)

	requireExportedKey(t, exportDir, upk)

	aapk := ts.GetAccountPublicKey(t, "AA")
	requireExportedKey(t, exportDir, aapk)

	uupk := ts.GetUserPublicKey(t, "AA", "UU")
	requireExportedKey(t, exportDir, uupk)

	requireExportedKey(t, exportDir, xpk)
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

func Test_ExportXKeyNotReferenced(t *testing.T) {
	ts := NewEmptyStore(t)
	defer ts.Done(t)

	exportDir := filepath.Join(ts.Dir, "export")

	_, xPK, kp := CreateCurveKey(t)
	ts.KeyStore.Store(kp)
	_, _, err := ExecuteCmd(createExportKeysCmd(), "--dir", exportDir, "--curve", xPK, "--not-referenced")
	require.NoError(t, err)
	requireExportedKey(t, exportDir, xPK)
}

func Test_ExportXKeyInContext(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	_, uPK, _ := CreateUserKey(t)
	_, _, err := ExecuteCmd(createEditAuthorizationCallout(), "--auth-user", uPK, "--curve", "generate")
	require.NoError(t, err)

	ac, err := ts.Store.ReadAccountClaim("A")
	require.NoError(t, err)
	xPK := ac.Authorization.XKey
	require.NotEmpty(t, xPK)

	exportDir := filepath.Join(ts.Dir, "export")
	_, _, err = ExecuteCmd(createExportKeysCmd(), "--dir", exportDir, "--curves")
	require.NoError(t, err)
	requireExportedKey(t, exportDir, xPK)

	exportDir = filepath.Join(ts.Dir, "export2")
	_, _, err = ExecuteCmd(createExportKeysCmd(), "--dir", exportDir, "-A")
	require.NoError(t, err)
	requireExportedKey(t, exportDir, xPK)
}

func Test_ExportKeyJwt(t *testing.T) {
	ts := NewTestStore(t, "O")
	defer ts.Done(t)

	ts.AddAccount(t, "A")
	ts.AddUser(t, "A", "U")

	o := ts.GetOperatorPublicKey(t)
	a := ts.GetAccountPublicKey(t, "A")
	u := ts.GetUserPublicKey(t, "A", "U")

	exportDir := filepath.Join(ts.Dir, "export")
	_, _, err := ExecuteCmd(createExportKeysCmd(), "--dir", exportDir, "-A", "--include-jwts")
	require.NoError(t, err)
	requireExportedKey(t, exportDir, o)
	require.FileExists(t, filepath.Join(exportDir, fmt.Sprintf("%s.jwt", o)))
	requireExportedKey(t, exportDir, a)
	require.FileExists(t, filepath.Join(exportDir, fmt.Sprintf("%s.jwt", a)))
	requireExportedKey(t, exportDir, u)
	require.FileExists(t, filepath.Join(exportDir, fmt.Sprintf("%s.jwt", u)))
}
