/*
 * Copyright 2018-2020 The NATS Authors
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
	"archive/zip"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	jwtv1 "github.com/nats-io/jwt"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/stretchr/testify/require"
)

func storeOperatorKey(t *testing.T, ts *TestStore, kp nkeys.KeyPair) {
	t.Helper()
	ts.OperatorKey = kp
	_, err := ts.KeyStore.Store(kp)
	require.NoError(t, err)
}

func makeNonManaged(t *testing.T, ts *TestStore, opName string, kp nkeys.KeyPair) {
	t.Helper()
	storeFile := filepath.Join(ts.Dir, "store", opName, ".nsc")
	require.FileExists(t, storeFile)
	d, err := Read(storeFile)
	require.NoError(t, err)
	var info store.Info
	json.Unmarshal(d, &info)
	require.True(t, info.Managed)
	info.Managed = false
	require.Equal(t, opName, info.Name)
	err = WriteJson(storeFile, info)
	require.NoError(t, err)
	storeOperatorKey(t, ts, kp)
}

func checkJwtVersion(t *testing.T, ts *TestStore, opName string, version int, token string) {
	t.Helper()
	target := filepath.Join(ts.Dir, "store", opName, fmt.Sprintf("%s.jwt", opName))
	require.FileExists(t, target)
	d, err := Read(target)
	require.NoError(t, err)
	oc, err := jwt.DecodeOperatorClaims(string(d))
	require.NoError(t, err)
	require.Equal(t, oc.Name, opName)
	require.Equal(t, oc.Version, version)
	if token != "" {
		require.Equal(t, string(d), token)
	}
}

func executeFailingCmd(t *testing.T, args ...string) {
	t.Helper()
	_, _, err := ExecuteCmd(rootCmd, args...) // could be any command
	require.Error(t, err)
	require.Contains(t, err.Error(), "this version of nsc only supports jwtV2")
	require.Contains(t, err.Error(), "upgrade-jwt")
}

func executePassingCmd(t *testing.T, args ...string) {
	t.Helper()
	_, _, err := ExecuteCmd(rootCmd, args...) // could be any command
	require.NoError(t, err)
}

func createOperator(t *testing.T, tempDir string, opName string) (fileV1 string, tokenV1 string, fileV2 string, tokenV2 string, kp nkeys.KeyPair, pub string) {
	var err error
	_, pub, kp = CreateOperatorKey(t)

	ocV1 := jwtv1.NewOperatorClaims(pub)
	ocV1.Name = opName
	tokenV1, err = ocV1.Encode(kp)
	require.NoError(t, err)

	ocV2 := jwt.NewOperatorClaims(pub)
	ocV2.Name = opName
	tokenV2, err = ocV2.Encode(kp)
	require.NoError(t, err)

	fileV1 = filepath.Join(tempDir, fmt.Sprintf("%s.v1.jwt", opName))
	err = Write(fileV1, []byte(tokenV1))
	require.NoError(t, err)

	fileV2 = filepath.Join(tempDir, fmt.Sprintf("%s.v2.jwt", opName))
	err = Write(fileV2, []byte(tokenV2))
	require.NoError(t, err)
	require.NotEqual(t, tokenV1, tokenV2)
	return
}

func TestUpgradeNonManaged(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	_, token, _, _, kp, _ := createOperator(t, tempDir, "O")
	ts := NewTestStoreWithOperatorJWT(t, token)
	defer ts.Done(t)
	makeNonManaged(t, ts, "O", kp)
	checkJwtVersion(t, ts, "O", 1, token)
	executeFailingCmd(t, "list", "keys")                     // could be any command
	executeFailingCmd(t, "edit", "operator", "--tag", "foo") // try writing operator
	executePassingCmd(t, "env")                              // only few exceptions

	_, _, err = ExecuteInteractiveCmd(rootCmd, []interface{}{false, false}, "upgrade-jwt") // only works in interactive mode
	require.NoError(t, err)
	checkJwtVersion(t, ts, "O", 1, token)
	_, _, err = ExecuteInteractiveCmd(rootCmd, []interface{}{false, true}, "upgrade-jwt")
	require.NoError(t, err)

	checkJwtVersion(t, ts, "O", 2, "")
	executePassingCmd(t, "list", "keys")                     // retry earlier command
	executePassingCmd(t, "edit", "operator", "--tag", "foo") // try writing operator
	checkJwtVersion(t, ts, "O", 2, "")
}

func TestUpgradeNoKeyNonManaged(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	_, token, _, _, kp, pub := createOperator(t, tempDir, "O")
	ts := NewTestStoreWithOperatorJWT(t, token)
	defer ts.Done(t)
	makeNonManaged(t, ts, "O", kp)
	err = ts.KeyStore.Remove(pub)
	require.NoError(t, err)
	checkJwtVersion(t, ts, "O", 1, token)
	executeFailingCmd(t, "list", "keys")                     // could be any command
	executeFailingCmd(t, "edit", "operator", "--tag", "foo") // try writing operator
	executePassingCmd(t, "env")                              // only few exceptions

	_, stdErr, err := ExecuteInteractiveCmd(rootCmd, []interface{}{}, "upgrade-jwt") // only works in interactive mode
	require.NoError(t, err)
	require.Contains(t, stdErr, "Identity Key for Operator")
	require.Contains(t, stdErr, "you need to restore it for this command to work")
	checkJwtVersion(t, ts, "O", 1, token)
	storeOperatorKey(t, ts, kp)
	_, _, err = ExecuteInteractiveCmd(rootCmd, []interface{}{false, true}, "upgrade-jwt")
	require.NoError(t, err)

	checkJwtVersion(t, ts, "O", 2, "")
	executePassingCmd(t, "list", "keys")                     // retry earlier command
	executePassingCmd(t, "edit", "operator", "--tag", "foo") // try writing operator
	checkJwtVersion(t, ts, "O", 2, "")
}

func TestUpgradeManaged(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	_, tokenV1, tfV2, tokenV2, _, _ := createOperator(t, tempDir, "O")
	ts := NewTestStoreWithOperatorJWT(t, tokenV1)
	defer ts.Done(t)
	checkJwtVersion(t, ts, "O", 1, tokenV1)
	executeFailingCmd(t, "list", "keys") // could be any command
	executePassingCmd(t, "env")          // only few exceptions

	_, stdErr, err := ExecuteInteractiveCmd(rootCmd, []interface{}{false}, "upgrade-jwt") // only works in interactive mode
	require.NoError(t, err)
	require.Contains(t, stdErr, "Your store is in managed mode")
	require.Contains(t, stdErr, "nsc add operator --force --url")
	checkJwtVersion(t, ts, "O", 1, tokenV1) // assert nothing was changed

	executePassingCmd(t, "add", "operator", "--force", "--url", tfV2)
	checkJwtVersion(t, ts, "O", 2, tokenV2) // assert nothing was changed
	executePassingCmd(t, "list", "keys")    // retry earlier command
}

func TestUpgradeBackup(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	_, token, _, _, kp, _ := createOperator(t, tempDir, "O")
	ts := NewTestStoreWithOperatorJWT(t, token)
	defer ts.Done(t)
	makeNonManaged(t, ts, "O", kp)
	checkJwtVersion(t, ts, "O", 1, token)
	backup := filepath.Join(ts.Dir, "test.zip")
	_, _, err = ExecuteInteractiveCmd(rootCmd, []interface{}{true, backup, false}, "upgrade-jwt") // only works in interactive mode
	require.NoError(t, err)
	closer, err := zip.OpenReader(backup)
	defer closer.Close()
	require.NoError(t, err)
	require.Len(t, closer.File, 2) // .nsc and O.jwt
}
